package main

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// Écran hôte : le seul modèle Bubble Tea du plein écran.
//
// Il dessine les barres et le cadre, et affiche à l'intérieur un sous-écran à
// la fois (formulaire, progression, résultat…). Les parcours, eux, ne
// changent pas : ils tournent dans leur propre goroutine et confient chaque
// sous-écran à l'hôte par afficher, qui bloque jusqu'à sa fin. C'est un
// guichet : le parcours dépose sa demande, attend, et repart avec la réponse.
//
// Relais : la demande part par programme.Send, et la réponse revient par un
// canal propre à cette demande. Aucun champ de l'hôte n'est donc partagé
// entre goroutines — seule la goroutine de l'interface les lit et les écrit —
// et aucun verrou n'est tenu pendant un Send, qui peut attendre que la boucle
// de Bubble Tea soit libre.

// errMenu : l'utilisateur a abandonné l'opération par Échap. Le parcours
// remonte jusqu'au menu sans rien écrire.
var errMenu = errors.New("retour au menu")

// sousEcran est ce que l'hôte sait afficher : un modèle, son nom dans le fil
// d'Ariane, et les touches qu'il annonce dans la barre du bas.
type sousEcran interface {
	tea.Model
	Touches() string
	Titre() string
}

// ecranDeSaisie est facultatif : un sous-écran qui attend du texte garde
// alors toutes les touches imprimables, ? compris — une phrase de passe peut
// en contenir.
type ecranDeSaisie interface{ saisitDuTexte() bool }

// ecranGardeEchap est facultatif : un sous-écran pour qui Échap a déjà un
// sens (l'explorateur remonte d'un dossier) ou ne doit rien abandonner (une
// écriture déjà lancée) la garde pour lui.
type ecranGardeEchap interface{ gardeEchap() bool }

// touchesGlobales sont valables partout, donc toujours rappelées.
const touchesGlobales = "? aide  ctrl+c quitter"

// resultatEcran est la réponse rendue au parcours : le modèle final, qui
// porte ce que l'écran a recueilli, et la façon dont il s'est terminé.
type resultatEcran struct {
	modele tea.Model
	err    error
}

// demandeEcran voyage de la goroutine du parcours vers l'hôte. Le canal a une
// place : l'hôte y dépose la réponse sans jamais attendre le parcours.
type demandeEcran struct {
	ecran   sousEcran
	reponse chan resultatEcran
}

func nouvelleDemande(ecran sousEcran) demandeEcran {
	return demandeEcran{ecran: ecran, reponse: make(chan resultatEcran, 1)}
}

// finEcranMsg : le sous-écran numéro id s'est terminé (tea.Quit, ou
// tea.Interrupt traduit en err).
type finEcranMsg struct {
	id  uint64
	err error
}

// messageEcran porte un message produit par une commande du sous-écran id.
// Le numéro permet de jeter ce qui arrive après sa fin : un tick
// d'animation en retard ne doit pas atterrir dans l'écran suivant, où il
// lancerait une seconde boucle d'animation.
type messageEcran struct {
	id  uint64
	msg tea.Msg
}

// operationMsg change l'opération affichée dans le fil d'Ariane.
type operationMsg string

// phraseGardeeMsg : le parcours vient de garder une phrase pour la session.
// L'hôte arme alors le minuteur d'oubli.
type phraseGardeeMsg struct{}

// echeancePhraseMsg : le minuteur d'oubli est arrivé. La phrase est oubliée si
// aucune touche n'a repoussé l'échéance entre-temps.
type echeancePhraseMsg struct{}

type hote struct {
	// envoyer remet un message à la boucle de Bubble Tea : programme.Send en
	// vrai, une fonction de test sinon. Seul champ lu hors de l'interface,
	// avec termine, et jamais modifié après la construction.
	envoyer func(tea.Msg)
	// termine est fermé quand plus personne n'affichera rien (Ctrl+C, ou le
	// programme est sorti) : afficher rend alors la main au lieu d'attendre
	// une réponse qui ne viendra pas.
	termine   chan struct{}
	fermeture sync.Once
	// quitte : le parcours a demandé la fin (menu « quitter »). Une sortie
	// sans lui vient d'ailleurs — signal, panne — et compte comme une
	// interruption.
	quitte atomic.Bool

	// Tout ce qui suit n'est touché que par la goroutine de l'interface.
	largeur, hauteur int
	courant          sousEcran
	demande          demandeEcran
	idCourant        uint64 // 0 : aucun écran
	prochainID       uint64
	operation        string
	aideOuverte      bool

	// phrase est la phrase gardée de la session, nil sans session. Elle a
	// son propre verrou : le parcours y écrit depuis sa goroutine.
	phrase *phraseSession
	// minuterie programme le minuteur d'oubli : tea.Tick en vrai, une
	// minuterie de test sinon — aucun test n'attend cinq minutes.
	minuterie func(time.Duration) tea.Cmd
	// minuteurArme : un minuteur d'oubli est en attente. Il n'y en a jamais
	// plus d'un : une touche repousse l'échéance sans en programmer d'autre,
	// et c'est à son arrivée qu'on regarde s'il faut en relancer un.
	minuteurArme bool
}

func nouvelHote(envoyer func(tea.Msg)) *hote {
	return &hote{envoyer: envoyer, termine: make(chan struct{}), prochainID: 1, minuterie: minuterieOubli}
}

// minuterieOubli programme un seul réveil, à l'échéance : aucune boucle ne
// tourne au repos pour surveiller l'inactivité.
func minuterieOubli(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return echeancePhraseMsg{} })
}

// afficher confie un sous-écran à l'hôte et attend sa fin. Appelée depuis la
// goroutine d'un parcours, jamais depuis celle de l'interface : elle s'y
// bloquerait elle-même.
//
// Retour : nil si l'écran s'est terminé normalement, errMenu sur Échap,
// huh.ErrUserAborted sur Ctrl+C ou si l'interface est déjà fermée.
func (h *hote) afficher(ecran sousEcran) (tea.Model, error) {
	select {
	case <-h.termine:
		return nil, huh.ErrUserAborted
	default:
	}
	demande := nouvelleDemande(ecran)
	h.envoyer(demande)
	select {
	case r := <-demande.reponse:
		return r.modele, r.err
	case <-h.termine:
		// Ctrl+C a pu déposer la réponse juste avant de fermer : le select
		// choisit au hasard entre deux cas prêts, on préfère la réponse,
		// qui porte le modèle final.
		select {
		case r := <-demande.reponse:
			return r.modele, r.err
		default:
			return nil, huh.ErrUserAborted
		}
	}
}

// definirOperation change l'opération du fil d'Ariane. Elle passe par la
// boucle de Bubble Tea, comme afficher, pour ne pas écrire un champ que la
// vue est en train de lire.
func (h *hote) definirOperation(nom string) { h.envoyer(operationMsg(nom)) }

// signalerPhraseGardee prévient l'hôte qu'une phrase vient d'être gardée :
// il arme le minuteur d'oubli. L'indicateur, lui, suit la phrase elle-même.
func (h *hote) signalerPhraseGardee() { h.envoyer(phraseGardeeMsg{}) }

// quitter termine le programme à la demande du parcours. Le QuitMsg est
// envoyé tel quel, sans passer par Update : Bubble Tea le traite lui-même et
// sort de Run normalement.
func (h *hote) quitter() {
	h.quitte.Store(true)
	h.envoyer(tea.QuitMsg{})
}

// executer fait tourner le programme de l'hôte, puis libère toujours les
// parcours qui attendent encore (fermer) : sans ça, un parcours bloqué dans
// afficher le resterait pour toujours. C'est la seule façon de lancer
// l'hôte, pour que l'oubli soit impossible.
//
// interrompu vaut true sur Ctrl+C, ou si le programme est sorti sans que le
// parcours l'ait demandé.
func (h *hote) executer(p *tea.Program) (interrompu bool, err error) {
	defer h.fermer()
	_, err = p.Run()
	switch {
	case errors.Is(err, tea.ErrInterrupted), errors.Is(err, tea.ErrProgramKilled):
		return true, nil
	case err != nil:
		return false, err
	}
	return !h.quitte.Load(), nil
}

// fermer libère les parcours qui attendent encore, et oublie pour de bon la
// phrase de session. À appeler dès que le programme est sorti ; sans risque
// si c'est fait plusieurs fois.
//
// executer l'appelle toujours avant de rendre la main, et Ctrl+C dès la
// touche : la phrase est donc à zéro avant que main n'appelle os.Exit, quelle
// que soit la façon de sortir.
func (h *hote) fermer() {
	h.fermeture.Do(func() {
		h.phrase.fermer()
		close(h.termine)
	})
}

func (h *hote) Init() tea.Cmd { return nil }

func (h *hote) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Tout message arrivé après l'échéance efface la phrase sans attendre le
	// minuteur : au réveil d'une veille, celui-ci arrive en retard, et une
	// image de l'animation ou un retour de focus passe souvent avant lui. Le
	// coût : un verrou et deux lectures d'horloge par message, pas par image.
	h.phrase.restant()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h.largeur, h.hauteur = msg.Width, msg.Height
		return h, h.transmettre(h.tailleEcran())
	case demandeEcran:
		return h, h.ouvrir(msg)
	case operationMsg:
		h.operation = string(msg)
		return h, nil
	case phraseGardeeMsg:
		return h, h.armerOubli()
	case echeancePhraseMsg:
		h.minuteurArme = false
		return h, h.armerOubli()
	case finEcranMsg:
		if h.courant != nil && msg.id == h.idCourant {
			h.terminer(msg.err)
		}
		return h, nil
	case messageEcran:
		if h.courant == nil || msg.id != h.idCourant {
			return h, nil
		}
		return h, h.transmettre(msg.msg)
	case tea.KeyMsg:
		// Toute touche compte comme une présence, sur n'importe quel écran.
		h.phrase.repousser()
		return h, h.touche(msg)
	}
	return h, h.transmettre(msg)
}

// touche applique les touches globales, puis passe le reste au sous-écran.
func (h *hote) touche(k tea.KeyMsg) tea.Cmd {
	if k.Type == tea.KeyCtrlC {
		if h.courant != nil {
			h.terminer(huh.ErrUserAborted)
		}
		h.fermer()
		return tea.Interrupt
	}
	if h.aideOuverte {
		// Les touches qui ferment l'aide s'arrêtent là : ⏎ ou Échap ne
		// doivent rien décider pour l'écran resté en dessous.
		switch k.String() {
		case "?", "esc", "enter":
			h.aideOuverte = false
		}
		return nil
	}
	saisie := false
	if e, ok := h.courant.(ecranDeSaisie); ok {
		saisie = e.saisitDuTexte()
	}
	switch {
	case k.String() == "?" && !saisie:
		h.aideOuverte = true
		return nil
	case k.String() == "o" && !saisie && h.phrase.active():
		// Jamais pendant une saisie : o peut faire partie d'une phrase.
		h.phrase.oublier()
		return nil
	case k.Type == tea.KeyEsc && h.courant != nil:
		if e, ok := h.courant.(ecranGardeEchap); !ok || !e.gardeEchap() {
			h.terminer(errMenu)
			return nil
		}
	}
	return h.transmettre(k)
}

// armerOubli programme le minuteur d'oubli s'il en faut un : une phrase
// gardée, et aucun minuteur déjà en attente. Une phrase dont l'échéance est
// atteinte est oubliée sur-le-champ (restant), sans minuteur.
//
// La commande est rendue par Update lui-même, jamais par transmettre : elle
// n'appartient à aucun sous-écran, et ne doit pas être jetée quand l'écran
// change.
func (h *hote) armerOubli() tea.Cmd {
	if h.minuteurArme {
		return nil
	}
	reste, active := h.phrase.restant()
	if !active {
		return nil
	}
	h.minuteurArme = true
	return h.minuterie(reste)
}

// ouvrir installe le sous-écran d'une demande et lui donne tout de suite la
// taille du cadre : sans elle, il se dessinerait d'abord à la mauvaise
// largeur, puis sauterait à la bonne.
func (h *hote) ouvrir(d demandeEcran) tea.Cmd {
	select {
	case <-h.termine:
		d.reponse <- resultatEcran{modele: d.ecran, err: huh.ErrUserAborted}
		return nil
	default:
	}
	// Un parcours n'affiche qu'un écran à la fois, puisque afficher bloque.
	// Si une demande en remplace malgré tout une autre, l'ancienne reçoit
	// errMenu : laissée sans réponse, sa goroutine resterait bloquée.
	if h.courant != nil {
		h.terminer(errMenu)
	}
	h.courant, h.demande = d.ecran, d
	h.aideOuverte = false
	h.idCourant = h.prochainID
	h.prochainID++

	cmds := []tea.Cmd{etiqueter(h.idCourant, h.courant.Init())}
	if h.largeur > 0 {
		cmds = append(cmds, h.transmettre(h.tailleEcran()))
	}
	return tea.Batch(cmds...)
}

// terminer rend la réponse au parcours et libère le cadre. L'aide se ferme
// avec l'écran : laissée ouverte, elle cacherait la question suivante.
func (h *hote) terminer(err error) {
	h.demande.reponse <- resultatEcran{modele: h.courant, err: err}
	h.courant, h.demande, h.idCourant = nil, demandeEcran{}, 0
	h.aideOuverte = false
}

// transmettre passe un message au sous-écran courant et étiquette les
// commandes qu'il renvoie avec son numéro.
func (h *hote) transmettre(msg tea.Msg) tea.Cmd {
	if h.courant == nil {
		return nil
	}
	modele, cmd := h.courant.Update(msg)
	ecran, ok := modele.(sousEcran)
	if !ok {
		// Erreur de programmation, mais on ne l'avale pas : le parcours la
		// reçoit, et l'écran ne reste pas figé sans réponse.
		h.terminer(fmt.Errorf("sous-écran %T : Update a rendu %T, qui n'est pas un sousEcran", h.courant, modele))
		return nil
	}
	h.courant = ecran
	return etiqueter(h.idCourant, cmd)
}

// tailleEcran est la taille annoncée au sous-écran : l'intérieur du cadre.
func (h *hote) tailleEcran() tea.WindowSizeMsg {
	l, ht := tailleInterieure(h.largeur, h.hauteur)
	return tea.WindowSizeMsg{Width: l, Height: ht}
}

func (h *hote) View() string {
	// Avant la première taille, on ne sait pas où centrer : mieux vaut un
	// écran vide qu'une mise en page qui saute à l'image suivante.
	if h.largeur <= 0 || h.hauteur <= 0 {
		return ""
	}
	corps, titre, touches, globales := "", "", "", touchesGlobales
	switch {
	case h.aideOuverte:
		l, _ := tailleInterieure(h.largeur, h.hauteur)
		corps, titre, touches, globales = vueAide(l), "aide", touchesAide, "ctrl+c quitter"
	case h.courant != nil:
		corps, titre, touches = h.courant.View(), h.courant.Titre(), h.courant.Touches()
	}

	l := largeurCadre(h.largeur)
	indicateur := ""
	if h.phrase.active() {
		indicateur = "● phrase en mémoire"
	}
	haut := barre(filDAriane(h.operation, titre), indicateur, l, styleDim, styleAccent)
	bas := barre(touches, globales, l, styleFaint, styleFaint)
	return disposer(h.largeur, h.hauteur, haut, corps, bas)
}

// versionAffichee ajoute le « v » quand la version commence par un chiffre :
// goreleaser injecte « 2.4.0 », le Makefile « v2.4.0 » (git describe), et un
// build local garde « dev ». L'option -version, elle, rend la valeur brute.
func versionAffichee(v string) string {
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

// filDAriane : « chiffremento vX.Y.Z · <opération> › <étape> », les parties
// absentes omises.
func filDAriane(operation, etape string) string {
	fil := "chiffremento " + versionAffichee(version)
	separateur := " · "
	for _, partie := range []string{operation, etape} {
		if partie == "" {
			continue
		}
		fil += separateur + partie
		separateur = " › "
	}
	return fil
}

// paquetBubbletea reconnaît les messages internes de Bubble Tea (taille de
// fenêtre demandée, écran alternatif, impression…) : ils doivent atteindre
// le programme tels quels, sans étiquette, sinon il ne les reconnaît plus.
var paquetBubbletea = reflect.TypeOf(tea.QuitMsg{}).PkgPath()

// typeSuite est le type, non exporté, que rend une tea.Sequence. On le tient
// de Bubble Tea lui-même plutôt que de sa forme (une tranche de commandes) :
// si une version future change ce type, la reconnaissance suit, et rien
// d'autre qu'une vraie suite n'est pris pour elle.
var typeSuite = reflect.TypeOf(tea.Sequence(rienAFaire, rienAFaire)())

func rienAFaire() tea.Msg { return nil }

// etiqueter enveloppe une commande du sous-écran id : ses messages
// reviendront marqués de ce numéro, et sa demande de sortie (tea.Quit) ne
// fermera que le sous-écran, pas tout le programme.
func etiqueter(id uint64, cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() tea.Msg { return traduire(id, cmd()) }
}

func etiqueterTout(id uint64, cmds []tea.Cmd) []tea.Cmd {
	etiquetees := make([]tea.Cmd, len(cmds))
	for i, c := range cmds {
		etiquetees[i] = etiqueter(id, c)
	}
	return etiquetees
}

func traduire(id uint64, msg tea.Msg) tea.Msg {
	switch m := msg.(type) {
	case nil:
		return nil
	case tea.QuitMsg:
		return finEcranMsg{id: id}
	case tea.InterruptMsg:
		return finEcranMsg{id: id, err: huh.ErrUserAborted}
	case tea.BatchMsg:
		return tea.BatchMsg(etiqueterTout(id, m))
	}
	t := reflect.TypeOf(msg)
	if t.PkgPath() != paquetBubbletea {
		return messageEcran{id: id, msg: msg}
	}
	// tea.Sequence rend un type non exporté, qu'on ne peut pas nommer dans un
	// case : on le reconnaît à son identité (typeSuite). Ses commandes doivent
	// être étiquetées elles aussi, sinon un tea.Quit placé dans une suite
	// fermerait tout le programme.
	if t == typeSuite {
		v := reflect.ValueOf(msg)
		cmds := make([]tea.Cmd, v.Len())
		for i := range cmds {
			cmds[i] = etiqueter(id, v.Index(i).Interface().(tea.Cmd))
		}
		suite := tea.Sequence(cmds...)
		if suite == nil {
			return nil
		}
		return suite()
	}
	return msg
}

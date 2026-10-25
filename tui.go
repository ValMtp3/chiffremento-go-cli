package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"chiffremento-cli/internal/zxcvbn"
	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"golang.org/x/term"
)

// isInteractive n'autorise la TUI que si les deux extrémités sont un
// terminal. Sinon on tomberait en marche dans un pipe ou un job de CI.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI lance l'interface guidée et rend le code de sortie de la session.
//
// En plein écran, un seul programme Bubble Tea tient le terminal (l'écran
// hôte, en écran alternatif) et les parcours tournent dans une goroutine qui
// lui confie chaque écran. Le menu revient après chaque opération, jusqu'à ce
// que l'utilisateur quitte : code 0 si tout a réussi, 1 si une opération au
// moins a échoué, 130 sur Ctrl+C, 129 si le terminal est fermé (SIGHUP), 2 si
// le parcours a paniqué (terminal rendu, temporaires supprimés, phrase
// oubliée, puis la panique imprimée).
//
// TERM=dumb garde le comportement d'avant : huh en mode accessible, sans
// écran alternatif, une seule opération ; l'erreur éventuelle remonte à main.
func runTUI() (int, error) {
	if os.Getenv("TERM") == "dumb" {
		// Pas de mode brut ici : Ctrl+C arrive en signal, et c'est le
		// gestionnaire global qui nettoie et sort en 130, comme avant.
		installSignalHandler()
		err := uneOperation(&choixMenu{action: "enc", mode: "saisie"})
		if errors.Is(err, errQuitter) {
			err = nil
		}
		return 0, err
	}

	s := &session{}
	var programme *tea.Program
	h := nouvelHote(func(msg tea.Msg) { programme.Send(msg) })
	programme = tea.NewProgram(h, optionsPleinEcran()...)
	// Posés avant le lancement du parcours et jamais remis à nil : un
	// parcours encore en vie après Ctrl+C (une dérivation Argon2 ne
	// s'interrompt pas) les lit sans verrou.
	hoteCourant, sessionCourante = h, s
	// L'hôte connaît la phrase de session : il arme le minuteur d'oubli et
	// l'efface à la sortie (fermer, appelé par executer et par Ctrl+C), donc
	// avant que main n'appelle os.Exit.
	h.phrase = &s.phrase
	return menerSession(h, s, programme, func() { parcoursSession(h, s) })
}

// fermerTemporaires est pkg.FermerTemporaires ; les tests la remplacent, le
// registre de pkg resterait sinon fermé pour la suite.
var fermerTemporaires = pkg.FermerTemporaires

// delaiFinParcours borne l'attente du parcours à la sortie : assez pour
// qu'une dérivation Argon2 en cours finisse (~1 s en profil standard, plus
// en « fort » ou « maximum » sur une machine lente), pas assez pour qu'un
// parcours bloqué retienne le processus. Au-delà, on sort quand même : les
// copies du mot de passe encore tenues par l'opération ne sont alors pas
// mises à zéro, comme avant. Une variable pour les tests.
var delaiFinParcours = 3 * time.Second

// menerSession fait tourner le programme de l'hôte pendant que parcours
// mène les opérations dans sa propre goroutine, puis rend le code de sortie.
//
// Sur une sortie qui n'est pas « quitter » (Ctrl+C, SIGHUP, panique), le
// parcours tourne peut-être encore : l'opération lancée ne s'interrompt pas,
// et ses copies du mot de passe ne sont mises à zéro que par ses defer, à sa
// fin. main fait os.Exit dès le retour : on attend donc la fin du parcours,
// au plus delaiFinParcours. Rien n'est effacé d'ici : un tampon encore lu par
// Argon2 depuis une autre goroutine ne doit jamais être touché.
func menerSession(h *hote, s *session, programme *tea.Program, parcours func()) (int, error) {
	// Fenêtre du terminal fermée : même nettoyage que Ctrl+C, sortie en 129.
	var raccroche atomic.Bool
	arreterRaccrochage := surRaccrochage(func() {
		raccroche.Store(true)
		fermerTemporaires()
		programme.Kill()
	})
	defer arreterRaccrochage()
	var garde gardeParcours
	parcoursFini := make(chan struct{})
	go func() {
		defer close(parcoursFini)
		garde.mener(parcours, func() {
			// Une panique dans le parcours tuerait le processus sur-le-champ :
			// écran alternatif affiché, terminal en mode brut, clair d'une
			// extraction laissé. On nettoie, on oublie la phrase, puis Kill
			// fait rendre la main à Run, qui rend le terminal.
			fermerTemporaires()
			h.fermer()
			programme.Kill()
		})
	}()

	interrompu, err := h.executer(programme)
	if interrompu || err != nil {
		// L'opération en cours (progression, changement de mot de passe)
		// tourne encore dans la goroutine du parcours. FermerTemporaires
		// supprime ses temporaires et l'empêche d'en créer d'autres ; puis
		// on la laisse finir, le temps borné qu'il faut.
		fermerTemporaires()
	}
	attendreBorne(parcoursFini, delaiFinParcours)
	// L'écran alternatif est quitté : ce qui y a été annoncé s'imprime
	// maintenant, sur le terminal ordinaire.
	s.imprimer(os.Stdout)
	fmt.Fprint(os.Stderr, noteVerrouillage())
	if note := garde.panique.Load(); note != nil {
		fmt.Fprintf(os.Stderr, "\nerreur interne : %v\n\n%s", note.valeur, note.pile)
		return exitErreurInterne, nil
	}
	if raccroche.Load() {
		return exitRaccroche, nil
	}
	switch {
	case err != nil:
		return 1, err
	case interrompu:
		return exitInterrompu, nil
	}
	return s.codeSortie(), nil
}

// attendreBorne attend que fini soit fermé, au plus delai. Le minuteur n'existe
// que pendant la sortie.
func attendreBorne(fini <-chan struct{}, delai time.Duration) {
	minuteur := time.NewTimer(delai)
	defer minuteur.Stop()
	select {
	case <-fini:
	case <-minuteur.C:
	}
}

// exitErreurInterne : le code d'une panique Go non rattrapée. Une panique du
// parcours, rattrapée pour rendre le terminal, sort avec le même.
const exitErreurInterne = 2

// paniqueParcours : ce qu'une panique du parcours laisse, sa valeur et la
// pile de la goroutine où elle est née.
type paniqueParcours struct {
	valeur any
	pile   []byte
}

// gardeParcours rattrape une panique de la goroutine du parcours.
type gardeParcours struct {
	panique atomic.Pointer[paniqueParcours]
}

// mener exécute parcours. S'il panique, la panique est notée, puis rendre
// est appelé : à lui de nettoyer et de faire sortir le programme. La pile est
// prise dans le recover, avant de quitter la goroutine : c'est la seule qui
// montre l'origine.
func (g *gardeParcours) mener(parcours, rendre func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		g.panique.Store(&paniqueParcours{valeur: r, pile: debug.Stack()})
		rendre()
	}()
	parcours()
}

// optionsPleinEcran : les réglages communs (sortie sur stderr, 30 images/s)
// et l'écran alternatif, qui rend au terminal son contenu à la sortie.
func optionsPleinEcran() []tea.ProgramOption {
	return append(optionsProgramme(), tea.WithAltScreen())
}

// errQuitter : l'utilisateur a choisi « quitter » au menu.
var errQuitter = errors.New("quitter")

// actionQuitter est la ligne « quitter » du menu.
const actionQuitter = "quitter"

// choixMenu porte les deux réponses du menu.
type choixMenu struct{ action, mode string }

// parcoursSession enchaîne les opérations jusqu'à « quitter » ou Ctrl+C.
// Tourne dans sa propre goroutine, jamais dans celle de l'interface.
//
// Une opération réussie finit sur sa carte résultat ; un échec est compté et
// finit sur l'écran d'erreur. Dans les deux cas, ⏎ ramène au menu. Échap
// avant le lancement y ramène directement, sans rien compter : rien n'a été
// écrit, il n'y a rien à montrer.
func parcoursSession(h *hote, s *session) {
	for {
		s.ouvrirOperation()
		// Le menu repart toujours de la première ligne : le curseur au même
		// endroit à chaque retour vaut mieux que la dernière opération faite.
		err := uneOperation(&choixMenu{action: "enc", mode: "saisie"})
		lignes := s.resumesOperation()
		var fin sousEcran
		switch {
		case errors.Is(err, errQuitter):
			h.quitter()
			return
		case errors.Is(err, huh.ErrUserAborted):
			// Ctrl+C : l'hôte est déjà fermé, le programme sort en 130.
			return
		case compteCommeEchec(err):
			s.noterEchec()
			fin = ecranErreurApres(lignes, err)
		case len(lignes) > 0:
			fin = carteResultat(lignes)
		}
		if fin == nil {
			continue
		}
		if _, err := h.afficher(fin); errors.Is(err, huh.ErrUserAborted) {
			return
		}
	}
}

// compteCommeEchec dit si une opération terminée par err a échoué. Un
// abandon voulu (Échap, Ctrl+C, quitter) n'est pas un échec.
func compteCommeEchec(err error) bool {
	switch {
	case err == nil, errors.Is(err, errMenu), errors.Is(err, errQuitter), errors.Is(err, huh.ErrUserAborted):
		return false
	}
	var a annulation
	return !errors.As(err, &a)
}

// annulation : l'utilisateur a refusé d'écraser la destination. Un choix, pas
// une panne : en plein écran, retour au menu sans échec. Hors plein écran
// (TERM=dumb), le message reste celui d'une erreur, comme avant.
type annulation struct{ dest string }

func (a annulation) Error() string { return "annulé : " + a.dest + " n'a pas été touché" }

// uneOperation montre le menu puis mène l'opération choisie jusqu'au bout.
//
// Deux formulaires successifs et non un seul à groupes masqués : le second est
// donc construit *après* que l'opération et le mode de saisie sont connus. Ça
// évite tout un nid de guêpes — un champ dont la configuration dépend d'un choix
// pas encore fait, et un explorateur que huh replie dès qu'on tente de revenir
// en arrière, laissant l'utilisateur devant une liste disparue.
//
// Le prix de ce découpage, c'est que la marche arrière est à notre charge :
// huh ne recule qu'à l'intérieur d'un formulaire. D'où les deux boucles — un
// écran qui rend errRetour renvoie à celui d'avant, et les réponses déjà
// données restent dans les variables, donc à l'écran.
func uneOperation(choix *choixMenu) error {
	path := ""
	// Les options de chiffrement vivent ici, et non dans tuiEncrypt : un « ← » de
	// trop sur la première question repasse par la boucle ci-dessous, et des
	// options déclarées plus bas seraient reconstruites à zéro — les neuf
	// réponses déjà données, mot de passe compris, disparaîtraient alors que la
	// grammaire de navigation promet le contraire.
	//
	// Elles sont en revanche remises à neuf quand la cible change : le choix de
	// compresser suit le fait que ce soit un dossier ou un fichier, et le nom du
	// fichier a pu peser sur les autres réponses. Et elles ne survivent pas à
	// l'opération : le menu suivant repart de zéro.
	var options optionsChiffrement
	optionsPour := ""
	for {
		nommerOperation("")
		if err := lancerMenu(choix); err != nil {
			return err
		}
		nommerOperation(nomOperation(choix.action))

		for {
			err := etapeCible(choix.action, choix.mode, &path)
			if errors.Is(err, errRetour) {
				break // retour au choix de l'opération
			}
			if err != nil {
				return err
			}

			switch choix.action {
			case "dec":
				err = tuiDecrypt(path)
			case "verify":
				err = tuiVerify(path)
			case "passwd":
				err = tuiPasswd(path)
			default:
				if path != optionsPour {
					options, optionsPour = optionsChiffrement{}, path
				}
				err = tuiEncrypt(path, &options)
			}
			if errors.Is(err, errRetour) {
				continue // retour au choix de la cible
			}
			return err
		}
	}
}

// nomOperation est le nom de l'opération dans le fil d'Ariane.
func nomOperation(action string) string {
	switch action {
	case "dec":
		return "déchiffrer"
	case "verify":
		return "vérifier"
	case "passwd":
		return "changer le mot de passe"
	default:
		return "chiffrer"
	}
}

// nommerOperation met à jour le fil d'Ariane, s'il y a un hôte.
func nommerOperation(nom string) {
	if h := hoteCourant; h != nil {
		h.definirOperation(nom)
	}
}

// lancerMenu montre le menu. Rend errQuitter si l'utilisateur part.
//
// En plein écran, le menu est un sous-écran à lui (menuModel) : il connaît q
// et la ligne « quitter », que le formulaire seul ne sait pas distinguer.
// Ailleurs (TERM=dumb), « quitter » se choisit comme une opération.
func lancerMenu(choix *choixMenu) error {
	h := hoteDuCadre()
	pleinEcran := h != nil
	form := choixForm(&choix.action, &choix.mode, pleinEcran)
	if !pleinEcran {
		if err := lancerEtape(form, nil); err != nil {
			return err
		}
	} else {
		m := &menuModel{etapeModel: etapeDansLeCadre(form, nil), action: &choix.action}
		m.titre = "menu"
		if _, err := h.afficher(m); err != nil {
			return err
		}
		if m.quitter {
			return errQuitter
		}
		if form.State == huh.StateAborted {
			return huh.ErrUserAborted
		}
	}
	if choix.action == actionQuitter {
		return errQuitter
	}
	return nil
}

// menuModel est le menu affiché par l'hôte : le formulaire du choix, plus
// la sortie (q, ou « quitter » validé).
type menuModel struct {
	*etapeModel
	action  *string
	quitter bool
}

func (m *menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && m.veutQuitter(k) {
		m.quitter = true
		*m.action = actionQuitter
		return m, tea.Quit
	}
	_, cmd := m.etapeModel.Update(msg)
	return m, cmd
}

// veutQuitter : q partout sur le menu, qui n'a aucun champ texte ; ou une
// touche de validation sur la ligne « quitter ». Sans cette dernière, huh
// passerait au champ suivant, « désigner la cible », qui n'a plus de sens.
// huh écrit la valeur à chaque mouvement du curseur : *m.action est donc
// la ligne surlignée.
func (m *menuModel) veutQuitter(k tea.KeyMsg) bool {
	if k.String() == "q" {
		return true
	}
	premier := m.form.GetFocusedField() == m.premier
	switch k.String() {
	case "enter", "right", "tab":
		return premier && *m.action == actionQuitter
	}
	return false
}

// gardeEchap : sur le menu, Échap ne fait rien — il n'y a rien à abandonner.
func (m *menuModel) gardeEchap() bool { return true }

// saisitDuTexte : le menu n'a que des listes ; ? y ouvre toujours l'aide.
func (m *menuModel) saisitDuTexte() bool { return false }

func (m *menuModel) Touches() string { return "↑↓ choisir  → valider  q quitter" }

// etapeCible demande la cible jusqu'à en obtenir une.
//
// La boucle est là parce que l'explorateur tolère une sélection vide pour ne
// pas bloquer la navigation : le formulaire se termine donc parfois sans rien
// proposer, et on le réaffiche au lieu de laisser filer un chemin vide vers une
// erreur obscure plus loin.
func etapeCible(action, mode string, path *string) error {
	for {
		form, ancre := cibleForm(action, mode, path)
		if err := lancerEtapeNommee("cible", form, ancre); err != nil {
			return err
		}
		*path = trimTrailingSeparator(strings.TrimSpace(expandHome(devirerGuillemets(*path))))
		if *path != "" {
			return nil
		}
	}
}

// choixForm demande l'opération et la façon de désigner la cible.
//
// La ligne « quitter » n'existe qu'en plein écran (avecQuitter), où le menu
// revient après chaque opération. En TERM=dumb, une seule opération est
// menée : le menu garde ses quatre lignes d'avant.
func choixForm(action *string, mode *string, avecQuitter bool) *huh.Form {
	operations := []huh.Option[string]{
		huh.NewOption("chiffrer un fichier ou un dossier", "enc"),
		huh.NewOption("déchiffrer un "+extension+"  (fichier ou dossier)", "dec"),
		huh.NewOption("vérifier un "+extension+"  (sans rien écrire)", "verify"),
		huh.NewOption("changer le mot de passe d'un "+extension, "passwd"),
	}
	if avecQuitter {
		operations = append(operations, huh.NewOption(actionQuitter, actionQuitter))
	}
	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Key("action").
				Title("opération").
				Options(operations...).
				Value(action),

			huh.NewSelect[string]().
				Key("mode").
				Title("désigner la cible").
				Options(
					huh.NewOption("saisir un chemin  (ou glisser-déposer)", "saisie"),
					huh.NewOption("parcourir les fichiers", "parcourir"),
				).
				Value(mode),
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
}

// cibleForm demande la cible, au clavier ou en naviguant. L'opération est déjà
// connue : le champ peut donc s'annoncer précisément.
//
// Le champ est rendu avec le formulaire : c'est l'ancre du retour en arrière,
// et lancerEtape a besoin de le reconnaître pour savoir qu'on est bien au
// premier champ de l'écran.
func cibleForm(action, mode string, path *string) (*huh.Form, huh.Field) {
	var champ huh.Field
	if mode == "parcourir" {
		champ = filePickerField(action, path)
	} else {
		champ = huh.NewInput().
			Key("path").
			Title(cibleTitre(action)).
			Placeholder(ciblePlaceholder(action)).
			Value(path).
			Validate(func(s string) error { return validateTarget(s, action) })
	}
	form := huh.NewForm(huh.NewGroup(champ)).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	return form, champ
}

// filePickerField construit l'explorateur. Il vient de huh, donc de bubbles :
// aucune dépendance nouvelle.
//
// Picking(true) est essentiel : sans lui, le champ affiche « No file selected. »
// et il faut appuyer sur une touche pour ouvrir l'arborescence. On veut la liste
// tout de suite — c'est la raison d'être du mode « parcourir ».
//
// Les permissions ne sont pas affichées : `drwxr-xr-x` n'aide personne à choisir
// un fichier et vole la place du nom. La taille, elle, sert. Les fichiers cachés
// sont visibles parce que c'est précisément le genre de fichier qu'on chiffre —
// une clé dans ~/.ssh, un fichier de configuration.
//
// Les dossiers ne sont sélectionnables qu'au chiffrement : ailleurs, seul un
// .chto a un sens. `validateTarget` reste l'autorité sur le reste, avec ses
// messages en français — `AllowedTypes` afficherait les siens en anglais et
// ferait exister deux règles là où il n'en faut qu'une.
func filePickerField(action string, path *string) huh.Field {
	// L'ordre des appels compte, et c'est un vrai piège de huh.
	//
	// NewFilePicker lit déjà le dossier à la construction. ShowHidden et Height
	// doivent donc venir en premier : posés plus loin dans la chaîne, le premier
	// n'a aucun effet — les fichiers cachés restent invisibles — et le second
	// soustrait la hauteur d'un titre rendu sans thème, ce qui ne laisse qu'une
	// seule ligne de liste. Dans les deux cas, rien ne plante : l'explorateur est
	// simplement inutilisable. TestCibleFormExplorateurListeAssezDEntrees garde
	// ces deux propriétés.
	//
	// Les fichiers cachés sont montrés parce que c'est précisément le genre de
	// fichier qu'on chiffre : une clé dans ~/.ssh, un fichier de configuration.
	return huh.NewFilePicker().
		ShowHidden(true).
		Height(16).
		Key("picker").
		Title(cibleTitre(action)).
		Description("↑↓ se déplacer · → ouvrir un dossier · ← remonter · entrée choisir").
		CurrentDirectory(".").
		// Picking : sans lui, le champ affiche « No file selected. » et il faut
		// appuyer sur une touche pour déplier l'arborescence. On veut la liste
		// tout de suite — c'est la raison d'être du mode « parcourir ».
		Picking(true).
		// Un dossier n'est une cible qu'au chiffrement ; ailleurs, seul un .chto
		// a un sens.
		DirAllowed(action == "enc").
		FileAllowed(true).
		// Les permissions ne sont pas affichées : `drwxr-xr-x` n'aide personne à
		// choisir un fichier et vole la place du nom. La taille, elle, sert.
		ShowSize(true).
		ShowPermissions(false).
		Value(path).
		// Une sélection vide ne bloque pas la navigation : sinon huh refuse de
		// quitter le champ tout en repliant la liste, et l'utilisateur se
		// retrouve devant un écran vide sans comprendre pourquoi. Le reste est
		// tranché par validateTarget, avec ses messages en français.
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return nil
			}
			return validateTarget(s, action)
		})
}

// cibleTitre nomme ce qu'on attend selon l'opération.
func cibleTitre(action string) string {
	switch action {
	case "enc":
		return "fichier ou dossier à chiffrer"
	case "passwd":
		return "fichier " + extension + " dont changer le mot de passe"
	default:
		return "fichier " + extension + " à lire"
	}
}

func ciblePlaceholder(action string) string {
	if action == "enc" {
		return "chemin, ou glisser-déposer le fichier ou le dossier"
	}
	return "chemin du fichier " + extension + ", ou glisser-déposer"
}

// validateTarget refuse tout de suite les cas qui échoueraient plus loin :
// chemin absent, dossier là où seul un .chto a du sens, ou extension
// incohérente avec l'opération.
func validateTarget(s, action string) error {
	s = trimTrailingSeparator(strings.TrimSpace(expandHome(s)))
	if s == "" {
		return errors.New("indique un fichier ou un dossier")
	}
	info, err := os.Stat(s)
	if err != nil {
		return errors.New("chemin introuvable")
	}
	if info.IsDir() && action != "enc" {
		return errors.New("c'est un dossier : seul un fichier " + extension + " peut être déchiffré ou vérifié")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("ce n'est ni un fichier régulier ni un dossier")
	}
	if action != "enc" && !strings.HasSuffix(s, extension) {
		return errors.New("ce fichier doit porter l'extension " + extension)
	}
	if action == "enc" && strings.HasSuffix(s, extension) {
		return errors.New("ce fichier est déjà chiffré")
	}
	return nil
}

// optionsChiffrement porte les réponses de l'écran des options. Un struct et
// non sept variables locales : l'écran est reconstruit à l'identique quand on y
// revient depuis la confirmation d'écrasement, et il doit alors rouvrir sur les
// réponses déjà données.
type optionsChiffrement struct {
	algo       byte
	kdf        pkg.KDFProfile
	compresser bool
	pad        bool
	padNiveau  pkg.PadProfile
	garderMeta bool
	brouiller  bool
	password   string
	confirm    string

	// genererPhrase remplace la saisie par une phrase de passe générée
	// (phrase_tui.go) ; phrase la porte une fois l'utilisateur certain de
	// l'avoir enregistrée.
	genererPhrase bool
	phrase        string

	// memoire : une phrase est gardée pour la session au moment d'afficher
	// l'écran, et la question qui la propose est donc posée. Ce n'est pas
	// une réponse : tuiEncrypt le relit à chaque affichage.
	memoire bool
	// saisirMalgreMemoire : l'utilisateur a écarté la phrase en mémoire. Le
	// zéro vaut « l'utiliser », le défaut voulu, sans toucher à
	// appliquerDefauts.
	saisirMalgreMemoire bool
	// forceMemoire : le verdict de force de la phrase en mémoire, montré sous
	// la question qui la propose (forcePhrase). Vide sans phrase.
	forceMemoire string
}

// secretChoisi rend le secret qui chiffrera le fichier : la phrase générée si
// elle a été choisie, la saisie sinon. Un mot de passe tapé puis abandonné au
// profit d'une phrase ne doit jamais servir à sa place.
func secretChoisi(o *optionsChiffrement) string {
	if o.genererPhrase {
		return o.phrase
	}
	return o.password
}

// encryptForm construit l'écran des options. Il rend aussi son premier champ :
// c'est l'ancre du retour vers le choix de la cible.
func encryptForm(o *optionsChiffrement, estDossier bool, tailleClair int64) (*huh.Form, huh.Field) {
	algoChamp := huh.NewSelect[byte]().
		Title("algorithme").
		Options(
			huh.NewOption("aes-256-gcm  (défaut)", pkg.AlgoAES),
			huh.NewOption("chacha20-poly1305", pkg.AlgoChaCha),
			huh.NewOption("cascade  chacha20 + aes  (parano)", pkg.AlgoCascade),
		).
		Value(&o.algo)

	form := huh.NewForm(
		huh.NewGroup(
			algoChamp,

			// La description montre la mémoire exigée, parce qu'elle le sera
			// aussi au déchiffrement : un fichier scellé en « maximum » ici sera
			// illisible sur une machine qui n'a pas 1 Gio à y consacrer.
			huh.NewSelect[pkg.KDFProfile]().
				Title("coût de la dérivation de clé").
				DescriptionFunc(func() string { return kdfHint(o.kdf) }, &o.kdf).
				Options(
					huh.NewOption("standard  (défaut)", pkg.KDFStandard),
					huh.NewOption("fort", pkg.KDFFort),
					huh.NewOption("maximum", pkg.KDFMaximum),
				).
				Value(&o.kdf),

			ouiNon("compresser avant chiffrement  (zstd)", compressHint(estDossier), &o.compresser),
		),

		// Le masquage de taille vit dans son propre groupe, escamoté dès qu'une
		// compression est choisie : proposer une option pour la refuser ensuite
		// est une impasse, autant ne pas la montrer. Un groupe masqué est aussi
		// sauté à la navigation, donc l'utilisateur passe directement au mot de
		// passe.
		huh.NewGroup(
			ouiNon("masquer la taille réelle",
				"arrondit la taille au palier supérieur (jusqu'à ~12 % de disque en plus)",
				&o.pad),
		).WithHideFunc(func() bool { return o.compresser }),

		// La largeur du palier est le seul réglage qui compte : elle décide
		// combien de fichiers sortent à la même taille, et ce que ça coûte. La
		// description l'exprime sur *ce* fichier — un pourcentage abstrait ne
		// dit rien, « 7,3 Mio → 8,0 Mio » se lit tout de suite.
		huh.NewGroup(
			huh.NewSelect[pkg.PadProfile]().
				Title("largeur du palier").
				DescriptionFunc(func() string { return padHint(tailleClair, o.padNiveau) }, &o.padNiveau).
				Options(
					huh.NewOption("standard  (défaut)", pkg.PadStandard),
					huh.NewOption("fort", pkg.PadFort),
					huh.NewOption("maximum  (puissance de deux)", pkg.PadMaximum),
				).
				Value(&o.padNiveau),
		).WithHideFunc(func() bool { return o.compresser || !o.pad }),

		huh.NewGroup(
			ouiNon("conserver le nom et la date d'origine",
				"stockés à l'intérieur du chiffré, donc restituables même sous un nom neutre",
				&o.garderMeta),
		).WithHideFunc(func() bool { return estDossier }),

		// Le brouillage dépend de la réponse précédente, d'où son propre groupe :
		// sans le nom gardé à l'intérieur, un nom tiré au hasard serait une perte
		// sèche. La question n'apparaît donc qu'une fois les métadonnées
		// conservées — et jamais pour un dossier, qui n'en porte pas.
		huh.NewGroup(
			ouiNon("brouiller le nom et la date du fichier chiffré",
				"sortie sous un nom tiré au hasard, datée du 1er janvier 2000\n"+
					"la date de création, elle, reste lisible dans le système de fichiers",
				&o.brouiller),
		).WithHideFunc(func() bool { return estDossier || !o.garderMeta }),

		// Générer plutôt qu'inventer : la phrase proposée vaut environ 128 bits,
		// bien au-delà de ce qu'un mot de passe tapé à la main atteint. Le
		// groupe de saisie disparaît alors, et l'écran de la phrase vient après
		// les options (etapePhrase).
		// Une phrase gardée pour la session est proposée d'abord. L'utiliser
		// saute la génération, la saisie et la confirmation : elle a déjà
		// servi à une opération réussie.
		huh.NewGroup(questionMemoire(&o.saisirMalgreMemoire, o.forceMemoire)).
			WithHideFunc(func() bool { return !o.memoire }),

		huh.NewGroup(
			questionFermee("mot de passe",
				fmt.Sprintf("une phrase de %d mots tirée au hasard (≈%.0f bits), ou un mot de passe de ton choix",
					pkg.DefautMotsPhrase, pkg.EntropiePhrase(pkg.DefautMotsPhrase)),
				"générer une phrase de passe", "le saisir moi-même", &o.genererPhrase),
		).WithHideFunc(func() bool { return depuisLaSession(o) }),

		huh.NewGroup(
			huh.NewInput().
				Title("mot de passe").
				// La description se recalcule à chaque frappe : l'utilisateur
				// voit la robustesse de son mot de passe pendant qu'il le tape.
				// Ce calcul tourne hors de la boucle de l'interface, d'où la
				// lecture par l'accesseur verrouillé — voir saisieVerrouillee.
				DescriptionFunc(indicateurDeForce(&o.password), &o.password).
				EchoMode(huh.EchoModePassword).
				Accessor(saisieVerrouillee{&o.password}).
				Validate(validatePassword),

			huh.NewInput().
				Title("confirmation").
				Description("une faute de frappe rendrait le fichier définitivement irrécupérable").
				EchoMode(huh.EchoModePassword).
				Value(&o.confirm).
				Validate(func(s string) error {
					if s != o.password {
						return errors.New("les deux saisies diffèrent")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return o.genererPhrase || depuisLaSession(o) }),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)

	return form, algoChamp
}

// appliquerDefauts renseigne des options neuves, et ne touche à rien d'autre.
//
// La distinction compte pour le retour en arrière : revenir sur cet écran doit
// retrouver les réponses déjà données, pas les remettre à zéro. Aucune valeur
// par défaut n'est le zéro de son type — AlgoAES vaut 1, les profils sont des
// chaînes non vides — donc la struct zéro désigne sans ambiguïté des options
// jamais renseignées.
func appliquerDefauts(o *optionsChiffrement, estDossier bool) {
	if *o != (optionsChiffrement{}) {
		return
	}
	o.algo, o.kdf, o.padNiveau = pkg.AlgoAES, pkg.KDFStandard, pkg.PadStandard
	o.compresser = estDossier
}

func tuiEncrypt(path string, o *optionsChiffrement) error {
	// Un dossier est presque toujours un mélange de texte, de code et de
	// métadonnées répétitives, et le tar ajoute lui-même beaucoup de zéros de
	// bourrage : la compression y gagne largement plus que sur un fichier
	// isolé. Elle est donc proposée déjà active — mais toujours refusable,
	// puisqu'elle laisse fuiter la compressibilité du contenu.
	estDossier := false
	if st, err := os.Stat(path); err == nil {
		estDossier = st.IsDir()
	}
	// zstd est le seul algorithme proposé : gzip n'est plus produit, seulement
	// relu pour les anciens fichiers. La question se réduit donc à « compresser
	// ou pas ».
	//
	// Les métadonnées ne concernent qu'un fichier : l'archive tar d'un dossier
	// porte déjà noms, dates et permissions de chaque entrée.
	appliquerDefauts(o, estDossier)

	// La taille sert à annoncer ce que coûterait chaque palier. Inconnue — un
	// dossier, un chemin illisible —, padHint se rabat sur les pourcentages.
	tailleClair := int64(-1)
	if taille, err := pkg.InputSize(path); err == nil && !estDossier {
		tailleClair = taille
	}

	// La boucle sert au retour depuis la question de l'écrasement : on
	// réaffiche les options, avec les réponses déjà saisies.
	for {
		o.memoire = phraseCourante().active()
		o.forceMemoire = ""
		if o.memoire {
			o.forceMemoire = forcePhrase(phraseCourante())
		}
		form, ancre := encryptForm(o, estDossier, tailleClair)
		if err := lancerEtapeNommee("options", form, ancre); err != nil {
			return err
		}

		// Le groupe du remplissage est masqué quand la compression est active,
		// mais masquer n'efface pas : un aller-retour dans le formulaire — pad à
		// oui, retour en arrière, compression à oui — laissait les deux posés, et
		// l'opération échouait plus loin sur « le remplissage et la compression
		// s'excluent ». C'est la compression, dernier choix visible, qui tranche.
		if o.compresser {
			o.pad = false
		}
		// Même raison pour le brouillage : son groupe disparaît si les
		// métadonnées ne sont plus conservées, mais un « oui » resté derrière
		// enverrait le fichier sous un nom que plus rien ne permettrait de
		// retrouver.
		if !o.garderMeta {
			o.brouiller = false
		}

		out := path + extension
		if o.brouiller {
			// Un nom tiré au hasard n'entre en collision avec rien : la question
			// de l'écrasement ne se pose donc pas, et nomBrouille a déjà vérifié
			// que la place est libre.
			nom, err := nomBrouille(path)
			if err != nil {
				return err
			}
			out = nom
		}
		ecraser := false
		if !o.brouiller {
			var err error
			ecraser, err = confirmerEcrasement(out)
			if errors.Is(err, errRetour) {
				continue // retour aux options
			}
			if err != nil {
				return err
			}
		}
		// La phrase se tire en dernier, juste avant de chiffrer, après la
		// question de l'écrasement : un retour depuis celle-ci ne fait donc
		// jamais tirer de phrase pour rien. Revenir aux options depuis l'écran
		// de la phrase en tire une nouvelle au passage suivant ; aucune n'est
		// utilisée avant d'avoir été confirmée comme enregistrée.
		depuisSession := depuisLaSession(o)
		if o.genererPhrase && !depuisSession {
			phrase, err := etapePhrase()
			if errors.Is(err, errRetour) {
				continue // retour aux options
			}
			if err != nil {
				return err
			}
			o.phrase = phrase
		}

		// La ligne « sel » du cadre reste sur une seule ligne : les mentions
		// s'y ajoutent plutôt que de casser la mise en page.
		salt := "16 o aléatoires · en-tête authentifié"
		switch {
		case estDossier && o.pad:
			salt = "16 o aléatoires · dossier tar · taille masquée"
		case estDossier:
			salt = "16 o aléatoires · dossier empaqueté en tar"
		case o.pad:
			salt = "16 o aléatoires · taille réelle masquée"
		}
		info := jobInfo{
			Action: "chiffrement",
			In:     path,
			Out:    out,
			AEAD:   pkg.AlgoName(o.algo),
			// Le profil choisi, pas le profil par défaut : afficher « m=256MiB »
			// alors que l'utilisateur venait de sélectionner « maximum » démentait
			// son propre choix à l'écran.
			KDF:     o.kdf.KDFLabel(),
			Salt:    salt,
			Success: out,
			Ecrit:   true,
		}
		// Une seule copie du mot de passe, en []byte, effacée à la sortie.
		//
		// La saisie elle-même reste une string : huh n'expose que ce type, et une
		// string Go est immuable — impossible de l'écraser sur place. On limite donc
		// ce qui est limitable : une copie unique au lieu d'une par appel, effacée
		// pour de bon, et la référence de la struct relâchée juste après. Le CLI,
		// lui, travaille en []byte de bout en bout (main.go).
		//
		// L'effacement n'a lieu qu'ici, après le lancement de l'opération : plus
		// haut, un retour en arrière doit encore retrouver la saisie à l'écran.
		//
		// La phrase de session, elle, arrive déjà en []byte (prendre) : aucune
		// string n'en est tirée. Oubliée depuis la question (délai, touche o),
		// on réaffiche les options, où la saisie est revenue.
		var motDePasse []byte
		if depuisSession {
			secret, ok := phraseCourante().prendre()
			if !ok {
				continue
			}
			motDePasse = secret
		} else {
			motDePasse = []byte(secretChoisi(o))
		}
		defer func() {
			zero(motDePasse)
			// Le mot de passe passe par l'accesseur : un calcul de robustesse
			// lancé par la dernière frappe peut encore être en train de le lire.
			saisieVerrouillee{&o.password}.Set("")
			o.confirm, o.phrase = "", ""
		}()

		// Relevé de la source avant le chiffrement : la suppression proposée
		// ensuite refusera d'effacer si quoi que ce soit a changé entre-temps.
		// Un échec ici n'empêche pas de chiffrer, seulement de supprimer : la
		// raison s'affiche à la place de la question.
		avant, errReleve := photographier(path)

		if err := runJob(info, func(p func(int64, int64)) error {
			return pkg.Encrypt(path, out, motDePasse, pkg.Options{
				Algo: o.algo, Comp: compEncodee(o.compresser), Pad: o.pad, PadProfile: o.padNiveau,
				KDF: o.kdf, Metadata: metaEncodee(o.garderMeta), Force: ecraser, Progress: p,
			})
		}); err != nil {
			return err
		}
		var errSuppression error
		if errReleve != nil {
			annoncer(os.Stdout, "  %s\n\n", styleFaint.Render(raisonSansReleve(errReleve)))
		} else {
			errSuppression = supprimerOriginal(path, out, motDePasse, estDossier, avant)
		}
		if o.brouiller {
			// La date se pose après coup : le fichier n'existe pas avant. Elle se
			// pose surtout en dernier, après supprimerOriginal — celui-ci relit le
			// chiffré en entier pour l'authentifier avant d'effacer l'original, et
			// cette lecture remet la date d'accès à l'heure réelle. Poser la date
			// neutre avant revenait à la faire défaire aussitôt : « ls -lu »
			// rendait l'heure du chiffrement.
			//
			// Un échec ici ne perd rien — le chiffré est écrit et valide — mais il
			// laisse la vraie date en place, donc il se dit. Le taire ferait
			// croire à une protection qui n'a pas eu lieu.
			if err := brouillerDate(out); err != nil {
				annoncer(os.Stderr, "  %s  %s\n\n", styleError.Render("!"), err)
			}
		}
		// Phrase tapée ou générée, opération réussie jusqu'au bout : on
		// propose de la garder. Pas si elle venait déjà de la session.
		if errSuppression != nil || depuisSession {
			return errSuppression
		}
		return proposerDeGarder(motDePasse)
	}
}

// passwordForm est l'écran commun au déchiffrement et à la vérification : le
// détail de l'en-tête, lisible sans mot de passe, puis le mot de passe. Il rend
// aussi le champ de saisie, ancre du retour vers le choix de la cible — la note
// qui le précède n'est pas sélectionnable, huh la saute.
func passwordForm(details string, password *string) (*huh.Form, huh.Field) {
	champ := champMotDePasse(password)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			champ,
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)

	return form, champ
}

// champMotDePasse est le champ masqué du déchiffrement et de la vérification.
func champMotDePasse(password *string) huh.Field {
	return huh.NewInput().
		Title("mot de passe").
		EchoMode(huh.EchoModePassword).
		Value(password).
		Validate(validatePassword)
}

func tuiDecrypt(path string) error {
	// L'en-tête est lisible sans mot de passe : on affiche les vrais
	// paramètres du fichier avant de demander quoi que ce soit.
	d, err := lireEnTete(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", d.Version, d.Algo, d.KDF)
	if d.Compressed {
		details += " · compressé"
	}
	if d.Archive {
		details += "\ncontient un dossier : il sera extrait dans " +
			filepath.Base(strings.TrimSuffix(path, extension)) + string(os.PathSeparator) +
			", qui ne doit pas déjà exister"
	}
	if d.Version < 3 {
		details += fmt.Sprintf("\nformat v%d, plus ancien que celui produit aujourd'hui : lecture seule, il sera relu tel quel", d.Version)
	}

	password := ""
	saisir := false // la phrase en mémoire, s'il y en a une, par défaut
	out := strings.TrimSuffix(path, extension)
	// La boucle sert au retour depuis la question de l'écrasement : on
	// redemande le mot de passe, déjà saisi et donc déjà rempli.
	for {
		form, ancre, proposee := formulaireMotDePasse(details, &password, &saisir)
		if err := lancerEtapeNommee("mot de passe", form, ancre); err != nil {
			return err
		}
		depuisSession := proposee && !saisir

		ecraser, err := confirmerEcrasement(out)
		if errors.Is(err, errRetour) {
			continue // retour au mot de passe
		}
		if err != nil {
			return err
		}
		info := jobInfo{
			Action:  "déchiffrement",
			In:      path,
			Out:     out,
			AEAD:    d.Algo,
			KDF:     d.KDF,
			Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
			Success: out,
			Ecrit:   true,
		}
		// DecryptTo et non Decrypt : le nom d'origine, quand le fichier en
		// porte un, ne remonte que par le résultat — Decrypt le jette. La
		// variable est écrite dans la goroutine de l'opération et lue après,
		// une fois que runJob a reçu sa fin.
		// Copie unique et effaçable du mot de passe, comme au chiffrement : la
		// saisie reste une string imposée par huh, mais rien n'oblige à en semer
		// des copies. L'effacement vient après la boucle de retour en arrière, qui
		// doit encore pouvoir réafficher la saisie.
		//
		// La phrase de session est prise le plus tard possible, juste avant
		// l'opération ; oubliée depuis la question, on redemande.
		motDePasse, ok := secretPourOperation(depuisSession, password)
		if !ok {
			continue
		}
		defer func() {
			zero(motDePasse)
			password = ""
		}()

		var meta *pkg.FileMetadata
		if err := runJob(info, func(p func(int64, int64)) error {
			res, err := pkg.DecryptTo(path, out, motDePasse, pkg.Options{Force: ecraser, Progress: p})
			meta = res.Metadata
			return err
		}); err != nil {
			return err
		}
		if err := restituerNom(out, meta); err != nil {
			return err
		}
		if err := supprimerChiffre(path); err != nil || depuisSession {
			return err
		}
		return proposerDeGarder(motDePasse)
	}
}

// restituerNom rend au fichier déchiffré le nom qu'il portait avant d'être
// chiffré, si son propriétaire le veut bien.
//
// Ce nom vit à l'intérieur du chiffré : il n'est lisible qu'une fois le contenu
// authentifié, donc bien après le choix de la destination — impossible de
// nommer la sortie avec avant de l'avoir vérifiée. D'où cette question posée
// après coup plutôt qu'un renommage d'autorité : la sortie porte le nom que
// l'utilisateur vient de choisir, le remplacer sans un mot serait une surprise.
// Le CLI, lui, se contente d'annoncer le nom — il n'a personne à qui demander.
func restituerNom(out string, meta *pkg.FileMetadata) error {
	if meta == nil || meta.Name == filepath.Base(out) {
		return nil
	}
	annoncer(os.Stdout, "  %s  %s\n\n", styleDim.Render("nom d'origine"), styleText.Render(meta.Name))

	cible, libre := cibleRestitution(out, meta)
	if !libre {
		annoncer(os.Stdout, "  %s\n\n", styleFaint.Render("un fichier de ce nom existe déjà ici : rien n'a été renommé"))
		return nil
	}

	// Le nom proposé est celui de la cible, pas celui d'origine : sous Windows il
	// a pu être adapté, et annoncer un nom que le renommage ne produira pas serait
	// mentir sur l'action. Quand les deux diffèrent, on le dit.
	nomCible := filepath.Base(cible)
	description := "il est pour l'instant enregistré sous " + filepath.Base(out)
	if nomCible != meta.Name {
		description += "\nson nom d'origine contient des caractères que ce système refuse : il sera adapté"
	}

	renommer := true
	champ := questionFermee(
		"lui rendre son nom ?",
		description,
		"renommer en "+nomCible, "garder "+filepath.Base(out), &renommer)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	// Sous le ✓ du déchiffrement, sans ancre : le fichier est déchiffré, il
	// n'y a plus d'écran où revenir.
	err := lancerQuestionApresResultat("nom d'origine", form)
	// Échap après l'écriture : le déchiffrement est fait, partir sans
	// répondre garde le nom actuel, comme « garder ».
	if errors.Is(err, errMenu) {
		return nil
	}
	if err != nil {
		return err
	}
	if !renommer {
		return nil
	}
	// Un renommage raté ne perd rien : le clair est écrit, authentifié et
	// complet, seul son nom reste celui de la sortie. Le remonter comme une
	// erreur ferait sortir en code 1 sur un déchiffrement réussi — et le cas
	// n'est pas théorique sous Windows, qui refuse « < > : " | ? * » et les noms
	// de périphériques réservés là où l'assainissement du nom d'origine, pensé
	// pour les séparateurs, les laisse passer.
	if err := os.Rename(out, cible); err != nil {
		annoncer(os.Stderr, "  %s  %s\n\n", styleError.Render("!"),
			fmt.Sprintf("renommage en %s impossible (%v) : le fichier reste sous %s",
				nomCible, err, filepath.Base(out)))
		return nil
	}
	annoncer(os.Stdout, "  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(cible))
	return nil
}

// cibleRestitution dit où irait le fichier s'il reprenait son nom d'origine, et
// si la place y est libre. Le nom a été assaini à la relecture — il ne porte
// plus ni séparateur ni « .. » — donc il reste dans le dossier de la sortie.
//
// Un nom déjà pris ne déclenche pas de proposition d'écrasement : personne ne
// veut se voir offrir de détruire un fichier juste après en avoir sauvé un.
func cibleRestitution(out string, meta *pkg.FileMetadata) (cible string, libre bool) {
	if meta == nil || meta.Name == "" {
		return "", false
	}
	// Le nom est adapté aux règles du système avant tout le reste : sous Windows,
	// « rapport 2024?.pdf » n'est pas un nom de fichier possible, et le renommage
	// échouerait après coup. Sous Unix, nomUtilisable est l'identité.
	nom := nomUtilisable(meta.Name)
	if nom == "" || nom == filepath.Base(out) {
		return "", false
	}
	cible = filepath.Join(filepath.Dir(out), nom)
	if _, err := os.Lstat(cible); err == nil {
		return cible, false
	}
	return cible, true
}

// tuiPasswd change le mot de passe sans re-chiffrer le contenu.
//
// Les trois champs tiennent sur un seul écran : l'actuel, le nouveau et sa
// confirmation. Le contrôle de l'actuel n'a lieu qu'à la validation, dans pkg —
// le vérifier champ par champ coûterait une dérivation Argon2 à chaque frappe.
func tuiPasswd(path string) error {
	d, err := lireEnTete(path)
	if err != nil {
		return err
	}
	if d.Version < pkg.VersionEnveloppe {
		return fmt.Errorf("ce fichier est au format v%d : son contenu est chiffré par une clé tirée du mot de passe, "+
			"il faut donc le déchiffrer puis le rechiffrer pour en changer", d.Version)
	}

	details := fmt.Sprintf("format v%d · %s · %s\nle contenu ne sera pas rechiffré : seul l'en-tête change", d.Version, d.Algo, d.KDF)
	ancien, nouveau, confirme := "", "", ""

	champ := huh.NewInput().
		Title("mot de passe actuel").
		EchoMode(huh.EchoModePassword).
		Value(&ancien).
		Validate(func(s string) error {
			if s == "" {
				return errors.New("indique le mot de passe actuel")
			}
			return nil
		})

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			champ,
			huh.NewInput().
				Title("nouveau mot de passe").
				// Même précaution qu'au chiffrement : l'indicateur se calcule
				// hors de la boucle de l'interface — voir saisieVerrouillee.
				DescriptionFunc(indicateurDeForce(&nouveau), &nouveau).
				EchoMode(huh.EchoModePassword).
				Accessor(saisieVerrouillee{&nouveau}).
				Validate(validatePassword),
			huh.NewInput().
				Title("confirmation").
				Description("une faute de frappe rendrait le fichier définitivement irrécupérable").
				EchoMode(huh.EchoModePassword).
				Value(&confirme).
				Validate(func(s string) error {
					if s != nouveau {
						return errors.New("les deux saisies diffèrent")
					}
					return nil
				}),
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)

	if err := lancerEtapeNommee("mots de passe", form, champ); err != nil {
		return err
	}

	// Copies effaçables des deux secrets, et les strings relâchées ensuite. Trois
	// saisies vivent sur cet écran, dont deux fois le nouveau mot de passe : c'est
	// le formulaire qui en concentre le plus.
	ancienOctets, nouveauOctets := []byte(ancien), []byte(nouveau)
	defer func() {
		zero(ancienOctets)
		zero(nouveauOctets)
		// Le nouveau mot de passe passe par l'accesseur : un calcul de
		// robustesse lancé par la dernière frappe peut encore le lire.
		saisieVerrouillee{&nouveau}.Set("")
		ancien, confirme = "", ""
	}()

	// Deux dérivations Argon2 sans progression à montrer : le cadre dit ce
	// qui se passe plutôt que de rester vide.
	err = enCours("mots de passe", "changement du mot de passe en cours…", func() error {
		return pkg.ChangePassword(path, ancienOctets, nouveauOctets)
	})
	if err != nil {
		return err
	}
	annoncer(os.Stdout, "  %s  %s\n", styleAccent.Render("✓"),
		styleText.Render("mot de passe changé, le contenu n'a pas été retouché"))
	annoncer(os.Stdout, "  %s\n\n", styleFaint.Render(avertissementRevocation))
	return nil
}

func tuiVerify(path string) error {
	d, err := lireEnTete(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", d.Version, d.Algo, d.KDF)
	if d.Compressed {
		details += " · compressé"
	}
	if d.Archive {
		details += " · dossier"
	}
	details += "\nrien ne sera écrit sur le disque"

	password := ""
	saisir := false // la phrase en mémoire, s'il y en a une, par défaut
	var motDePasse []byte
	depuisSession := false
	// La boucle ne resert que si la phrase en mémoire a été oubliée entre la
	// question et son usage (délai, touche o) : on redemande alors.
	for {
		form, ancre, proposee := formulaireMotDePasse(details, &password, &saisir)
		if err := lancerEtapeNommee("mot de passe", form, ancre); err != nil {
			return err
		}
		depuisSession = proposee && !saisir
		secret, ok := secretPourOperation(depuisSession, password)
		if ok {
			motDePasse = secret
			break
		}
	}

	info := jobInfo{
		Action:  "vérification",
		In:      path,
		Out:     "(rien, contrôle seul)",
		AEAD:    d.Algo,
		KDF:     d.KDF,
		Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
		Success: verifySucces(d.Archive),
	}
	defer func() {
		zero(motDePasse)
		password = ""
	}()
	err = runJob(info, func(p func(int64, int64)) error {
		return pkg.Verify(path, motDePasse, pkg.Options{Progress: p})
	})
	if err != nil || depuisSession {
		return err
	}
	return proposerDeGarder(motDePasse)
}

// teaOptions est vide en production. Les tests s'en servent pour faire
// tourner l'écran sans terminal, et donc vérifier sa durée réelle.
var teaOptions []tea.ProgramOption

// runJob lance l'opération dans une goroutine et affiche l'écran animé.
//
// En plein écran, l'écran de progression est un sous-écran de l'hôte, dans
// le cadre ; sinon (TERM=dumb, tests sans terminal) il a son propre
// programme.
func runJob(info jobInfo, op func(progress func(done, total int64)) error) error {
	if h := hoteDuCadre(); h != nil {
		return runJobDansHote(h, info, op)
	}
	return runJobSeul(info, op)
}

// lancerOperation démarre op dans sa goroutine et rend l'écran qui la suit :
// op dépose son avancement dans un compteur atomique et sa fin dans un canal,
// que l'écran attend (progressModel.Init). Le canal a une place : la
// goroutine de l'opération n'attend jamais l'écran, même s'il est déjà fermé.
// finie est fermé quand op a rendu la main, quoi qu'il soit arrivé à l'écran.
func lancerOperation(info jobInfo, op func(progress func(done, total int64)) error, largeur int) (model *progressModel, finie <-chan struct{}) {
	if size, err := pkg.InputSize(info.In); err == nil {
		info.Size = size
	}
	done := new(atomic.Int64)
	fin := make(chan error, 1)
	fini := make(chan struct{})
	model = newProgressModel(info, done, largeur)
	model.fin = fin
	go func() {
		defer close(fini)
		err := op(func(d, _ int64) { done.Store(d) })
		// La sortie est sur le disque, mais son ✓ attendra la fin de
		// l'animation : noté ici, à l'instant même, il survit à un Ctrl+C
		// pendant ces quelques secondes (session.imprimer).
		if s := sessionCourante; err == nil && info.Ecrit && s != nil {
			s.noterEcritAvantInterruption(fmt.Sprintf("  %s  %s\n\n", styleAccent.Render("✓"),
				styleText.Render(info.Out+" écrit avant l'interruption")))
		}
		fin <- err
	}()
	return model, fini
}

// runJobDansHote affiche la progression dans le cadre de l'hôte.
//
// Ctrl+C : l'hôte ferme l'écran et afficher rend huh.ErrUserAborted alors
// que l'opération tourne encore. Pas d'os.Exit ici : le programme de l'hôte
// sort en interruption, et runTUI nettoie les temporaires avant de rendre 130
// à main. Une opération qui finirait malgré tout après ce nettoyage ne peut
// plus basculer son temporaire sur la destination (pkg.basculer).
//
// En attendant la sortie du processus, runJob ne rend pas la main avant la
// fin de l'opération : l'appelant effacerait sinon le mot de passe (zero)
// pendant qu'Argon2 ou le chiffrement le lisent encore.
func runJobDansHote(h *hote, info jobInfo, op func(progress func(done, total int64)) error) error {
	// Ctrl+C a pu fermer l'hôte juste avant : l'opération ne doit alors
	// même pas commencer, elle écrirait pendant que le processus sort.
	select {
	case <-h.termine:
		return huh.ErrUserAborted
	default:
	}
	// La largeur de départ est provisoire : l'hôte donne celle du cadre dès
	// l'ouverture de l'écran.
	ecran, finie := lancerOperation(info, op, contentWidth+2)
	final, err := h.afficher(ecran)
	if err != nil {
		<-finie
		return err
	}
	model, ok := final.(*progressModel)
	if !ok {
		return fmt.Errorf("écran de progression : modèle final inattendu %T", final)
	}
	if model.err != nil {
		return model.err
	}
	// Le ✓ ordinaire prend le relais de la mention d'interruption.
	if s := sessionCourante; s != nil {
		s.confirmerEcrit()
	}
	annoncer(os.Stdout, "  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(info.Success))
	return nil
}

// runJobSeul affiche l'écran animé dans un programme à lui, à la largeur
// historique, avec son titre.
func runJobSeul(info jobInfo, op func(progress func(done, total int64)) error) error {
	model, _ := lancerOperation(info, op, contentWidth+2)
	model.autonome = true
	// Même cadence que les formulaires ; la sortie reste celle par défaut.
	prog := tea.NewProgram(model, append([]tea.ProgramOption{tea.WithFPS(imagesParSeconde)}, teaOptions...)...)

	if _, err := prog.Run(); err != nil {
		// Ctrl+C ferme l'écran mais ne prévient pas l'opération : sans cette
		// sortie franche, elle continuerait en arrière-plan, invisible, et un
		// ✓ arriverait après coup sur un terminal déjà rendu. On nettoie les
		// temporaires puis on quitte, comme le handler de signal — la mort du
		// processus est ce qui interrompt réellement le chiffrement.
		if errors.Is(err, tea.ErrInterrupted) || errors.Is(err, tea.ErrProgramKilled) {
			pkg.FermerTemporaires()
			fmt.Fprintln(os.Stderr, "\ninterrompu")
			os.Exit(exitInterrompu)
		}
		// Toute autre panne de l'affichage laisse l'opération en cours : la même
		// sortie franche s'impose, sinon le processus meurt sur le retour d'erreur
		// en abandonnant un .chto-tmp-* dans le dossier de l'utilisateur.
		pkg.FermerTemporaires()
		return err
	}
	// Le programme ne sort normalement qu'après doneMsg : l'erreur de
	// l'opération est alors dans le modèle.
	if model.err != nil {
		return model.err
	}

	annoncer(os.Stdout, "  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(info.Success))
	return nil
}

// --- Saisie du mot de passe hors TUI ------------------------------------

// readPassword récupère le mot de passe sans jamais le faire transiter par la
// ligne de commande : le flag -key de la v1 était visible dans `ps aux` pour
// tous les utilisateurs de la machine et finissait dans l'historique du shell.
//
// Trois chemins, dans cet ordre :
//
//   - stdinTaken (l'entrée standard porte les données, avec -in -) : le mot de
//     passe est demandé sur le terminal de contrôle, /dev/tty. Sans ce détour,
//     la première ligne des *données* serait lue comme mot de passe — un bug
//     silencieux qui chiffrerait le reste avec un secret involontaire.
//   - entrée standard qui n'est pas un terminal : on lit une ligne. C'est le
//     chemin des scripts, et il ne fuite ni dans ps ni dans les arguments :
//     echo 'motdepasse' | chiffremento -mode enc -in f
//   - terminal : saisie masquée.
func readPassword(confirm bool, stdinTaken bool) ([]byte, error) {
	if stdinTaken {
		return readPasswordFromTTY(confirm)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := lecteurStdin().ReadString('\n')
		if err != nil && line == "" {
			return nil, errors.New("aucun mot de passe reçu sur l'entrée standard")
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return nil, errors.New("mot de passe vide")
		}
		return []byte(pw), nil
	}

	password := ""
	field := huh.NewInput().
		Title("mot de passe").
		EchoMode(huh.EchoModePassword).
		Value(&password).
		Validate(validatePassword).
		WithTheme(formTheme())
	if err := lancerChamp(field); err != nil {
		return nil, err
	}

	if confirm {
		second := ""
		check := huh.NewInput().
			Title("confirmation").
			EchoMode(huh.EchoModePassword).
			Value(&second).
			Validate(func(s string) error {
				if s != password {
					return errors.New("les deux saisies diffèrent")
				}
				return nil
			}).
			WithTheme(formTheme())
		if err := lancerChamp(check); err != nil {
			return nil, err
		}
	}

	return []byte(password), nil
}

// readPasswordFromTTY demande le mot de passe au terminal de contrôle, l'entrée
// standard étant occupée par les données.
//
// huh n'est pas utilisable ici : il lit os.Stdin. On passe donc directement par
// term.ReadPassword sur /dev/tty, ce qui donne la même saisie masquée sans
// habillage.
// lecteurStdin rend un lecteur bufferisé partagé entre les appels.
//
// Un bufio.Reader neuf à chaque lecture avalait jusqu'à 4 Kio d'entrée pour n'en
// rendre qu'une ligne, et jetait le reste avec lui : la deuxième lecture ne
// trouvait plus rien. Invisible tant qu'une commande ne demandait qu'un mot de
// passe, fatal dès qu'elle en demande deux — c'est le cas de passwd.
//
// La source est comparée à chaque appel parce que les tests remplacent
// os.Stdin : un lecteur figé au démarrage lirait le mauvais descripteur.
//
// Sans garde de concurrence, volontairement : le parcours d'une commande est
// séquentiel, et deux saisies de mot de passe en parallèle n'auraient de toute
// façon aucun sens sur une entrée standard unique. Un futur mode qui lirait
// stdin depuis plusieurs goroutines devrait passer ce lecteur en paramètre
// plutôt que d'ajouter un verrou ici.
var (
	stdinLecteur *bufio.Reader
	stdinSource  *os.File
)

func lecteurStdin() *bufio.Reader {
	if stdinLecteur == nil || stdinSource != os.Stdin {
		stdinSource = os.Stdin
		stdinLecteur = bufio.NewReader(os.Stdin)
	}
	return stdinLecteur
}

func readPasswordFromTTY(confirm bool) ([]byte, error) {
	tty, err := os.OpenFile(ttyDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("l'entrée standard porte les données à chiffrer, "+
			"le mot de passe doit donc être saisi au terminal — introuvable ici (%w). "+
			"Utilise -in FICHIER plutôt que -in -", err)
	}
	defer tty.Close()

	if !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.New("le terminal de contrôle n'est pas utilisable pour une saisie masquée : " +
			"utilise -in FICHIER plutôt que -in -")
	}

	ask := func(prompt string) ([]byte, error) {
		fmt.Fprintf(tty, "%s ", styleDim.Render(prompt))
		defer surveillerTerminal(int(tty.Fd()))()
		pw, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return nil, fmt.Errorf("lecture du mot de passe: %w", err)
		}
		return pw, nil
	}

	password, err := ask("mot de passe :")
	if err != nil {
		return nil, err
	}
	if err := validatePassword(string(password)); err != nil {
		return nil, err
	}

	if confirm {
		second, err := ask("confirmation :")
		if err != nil {
			return nil, err
		}
		defer zero(second)
		if !bytes.Equal(password, second) {
			return nil, errors.New("les deux saisies diffèrent")
		}
	}
	return password, nil
}

func validatePassword(s string) error {
	if s == "" {
		return errors.New("le mot de passe ne peut pas être vide")
	}
	return nil
}

// Seuils de l'indicateur de force, en bits d'entropie estimée par zxcvbn.
//
// Ils sont calibrés sur une attaque *hors ligne* : l'attaquant a le fichier et
// calcule à son rythme. Argon2id à 256 MiB le limite à l'ordre de 10⁴
// tentatives par seconde même avec du matériel dédié, soit ~2¹³/s. À ce
// rythme, 35 bits tombent en une poignée de jours et 50 bits demandent des
// milliers d'années. D'où les deux paliers.
//
// Ces seuils sont bien plus bas que ceux de la v2.0 parce que la mesure a
// changé de nature : le compte combinatoire d'avant surestimait tout — il
// donnait 60 bits à « azerty123 » — là où zxcvbn compte le nombre réel de
// tentatives nécessaires.
const (
	bitsFaible  = 35
	bitsCorrect = 50

	// offlineGuessRate : hypothèse d'attaque, en tentatives par seconde.
	offlineGuessRate = 1e4
)

// passwordEntropy estime l'entropie en bits à partir du nombre de tentatives
// que zxcvbn juge nécessaires pour retrouver le mot de passe.
//
// zxcvbn ne compte pas les combinaisons possibles : il décompose la saisie en
// motifs (mots de dictionnaire, prénoms, dates, suites de touches, répétitions,
// l33t speak) et additionne le coût de chacun. C'est ce qui fait que
// « azerty123 » est désormais évalué à une vingtaine de bits au lieu d'une
// soixantaine. Ça reste un repère pour l'utilisateur, pas une garantie, et rien
// ne bloque la saisie.
func passwordEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	guesses := zxcvbn.PasswordStrength(s, nil).Guesses
	if guesses < 2 {
		return 0
	}
	return math.Log2(guesses)
}

// indicateurDeForce rend la description d'un champ de mot de passe : la force
// de la saisie, recalculée à chaque frappe.
//
// huh ne l'évalue que lorsque le groupe du champ est affiché. Son premier appel
// lance donc le chargement des listes de zxcvbn en arrière-plan, pendant que
// l'utilisateur commence à taper : la première frappe ne l'attend pas, et une
// phrase générée (groupe de saisie escamoté) ne charge rien (~9 Mo évités,
// mesuré en pty).
func indicateurDeForce(saisie *string) func() string {
	prechargement := sync.OnceFunc(func() { go zxcvbn.Precharger() })
	return func() string {
		prechargement()
		return strengthHint(saisieVerrouillee{saisie}.Get())
	}
}

// strengthHint traduit l'entropie en une ligne lisible, avec l'ordre de
// grandeur du temps qu'une attaque hors ligne y passerait.
func strengthHint(s string) string {
	if s == "" {
		return "jamais affiché, jamais visible dans ps ni dans l'historique"
	}
	bits := passwordEntropy(s)
	verdict := "solide"
	switch {
	case bits < bitsFaible:
		verdict = "faible, une phrase de passe serait bien plus sûre"
	case bits < bitsCorrect:
		verdict = "correct"
	}
	return fmt.Sprintf("~%.0f bits — %s · %s hors ligne", bits, verdict, crackTime(bits))
}

// crackTime donne l'ordre de grandeur, pas une prédiction : seule la puissance
// de dix compte, et l'hypothèse de débit peut se tromper d'un facteur cent.
func crackTime(bits float64) string {
	if bits <= 0 {
		return "instantané"
	}
	secondes := math.Pow(2, bits) / offlineGuessRate
	switch {
	case secondes < 60:
		return "cassé en quelques secondes"
	case secondes < 3600:
		return "cassé en quelques minutes"
	case secondes < 86400:
		return "cassé en quelques heures"
	case secondes < 30*86400:
		return "cassé en quelques jours"
	case secondes < 365*86400:
		return "cassé en quelques mois"
	case secondes < 1000*365*86400:
		return fmt.Sprintf("~%.0f ans", secondes/(365*86400))
	default:
		return "des millénaires"
	}
}

// verifySucces adapte la phrase de fin : sur une archive, ce qui est contrôlé
// est bien qu'elle serait extractible, pas seulement lisible.
func verifySucces(archive bool) string {
	if archive {
		return "archive intacte, extractible, rien écrit sur le disque"
	}
	return "fichier intact, déchiffrable, rien écrit sur le disque"
}

// confirmerEcrasement demande son avis à l'utilisateur quand la destination
// existe déjà, plutôt que de la remplacer en silence.
//
// C'est le pendant du drapeau -force du CLI : ici la question peut être posée,
// donc elle l'est. Un dossier n'est jamais proposé à l'écrasement — le
// remplacer voudrait dire supprimer une arborescence entière sur un simple
// « oui ».
//
// Le booléen rendu est la réponse réelle de l'utilisateur, et il alimente
// Options.Force. Poser Force à true d'office désarmait la garde de pkg pour
// toute la TUI, y compris quand il n'y avait rien à écraser et donc aucune
// question posée : un fichier apparu entre ce Lstat et l'écriture était
// détruit sans un mot. En rendant false quand la place est libre, on laisse
// pkg refaire le contrôle au moment d'écrire.
func confirmerEcrasement(dest string) (bool, error) {
	info, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // rien à cet emplacement : rien à demander
	}
	if err != nil {
		// Ni un fichier, ni une absence franche : un EACCES sur le parent
		// passait ici pour « la place est libre ».
		return false, fmt.Errorf("vérification de %s: %w", dest, err)
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s existe déjà et c'est un dossier : déplace-le ou renomme-le avant de continuer", dest)
	}

	ecraser := false
	champ := questionFermee(
		dest+" existe déjà — l'écraser ?",
		"son contenu actuel sera définitivement perdu",
		"écraser", "annuler", &ecraser)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	// L'ancre rend errRetour quand l'utilisateur recule : l'appelant réaffiche
	// alors ses options plutôt que d'abandonner l'opération. Reculer et annuler
	// ne disent pas la même chose — annuler arrête tout.
	if err := lancerEtapeNommee("écrasement", form, champ); err != nil {
		return false, err
	}
	if !ecraser {
		return false, annulation{dest: dest}
	}
	return true, nil
}

// compEncodee traduit la réponse de l'interface en identifiant de compression.
func compEncodee(compresser bool) byte {
	if compresser {
		return pkg.CompZstd
	}
	return pkg.CompNone
}

func compressHint(dossier bool) string {
	if dossier {
		return "proposée active sur un dossier · laisse fuiter la compressibilité du contenu"
	}
	return "réduit la taille, mais laisse fuiter la compressibilité du contenu"
}

// shellEchappeLesEspaces dit si l'hôte échappe les espaces d'un chemin avec des
// contre-obliques. Faux sous Windows, où la contre-oblique est le séparateur de
// chemin : « C:\Users\x\mes documents » y deviendrait « C:Usersxmes documents ».
//
// Une variable et non un test direct sur runtime.GOOS, pour que le test couvre
// les deux branches depuis n'importe quel système.
var shellEchappeLesEspaces = os.PathSeparator != '\\'

// devirerGuillemets nettoie un chemin collé dans le champ par un
// glisser-déposer : le terminal le livre quoté (« '/a/mon fichier.txt' ») ou
// échappé (« /a/mon\ fichier.txt »), et validateTarget répondrait « chemin
// introuvable » à un fichier qui existe.
//
// Le retrait des guillemets vaut partout — l'explorateur Windows quote lui aussi
// les chemins à espaces. Le déséchappement, lui, est réservé aux systèmes où la
// contre-oblique n'est pas un séparateur : ailleurs il détruirait le chemin au
// lieu de le réparer.
func devirerGuillemets(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 && (p[0] == '\'' || p[0] == '"') && p[len(p)-1] == p[0] {
		p = p[1 : len(p)-1]
	}
	if !shellEchappeLesEspaces || !strings.Contains(p, `\`) {
		return p
	}
	return strings.NewReplacer(`\ `, " ", `\'`, "'", `\"`, "\"").Replace(p)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			// filepath.Join et non une concaténation : sous Windows, coller
			// « /docs » à « C:\Users\x » produisait un chemin aux séparateurs
			// mélangés. Go l'accepte, mais il s'affiche mal partout.
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// kdfHint décrit un profil KDF pour la TUI. La mémoire est annoncée parce
// qu'elle sera aussi exigée au déchiffrement.
func kdfHint(p pkg.KDFProfile) string {
	return fmt.Sprintf("%s · %d Mio de mémoire, exigés aussi au déchiffrement",
		p.KDFLabel(), p.MemoryMiB())
}

// padHint décrit un palier de remplissage. Sur un fichier de taille connue, il
// montre le résultat plutôt qu'une règle : c'est le seul moyen de choisir en
// connaissance de cause, le coût d'un même profil allant de quelques pour cent
// à un doublement selon la taille.
func padHint(tailleClair int64, p pkg.PadProfile) string {
	if tailleClair <= 0 {
		return padRegle(p)
	}
	bas, haut := pkg.PadFenetre(tailleClair, p)
	surcout := float64(haut-tailleClair) / float64(tailleClair) * 100
	return fmt.Sprintf("%s → environ %s  (+%.1f %%) · tout ce qui pèse de %s à %s sort identique",
		humanSize(tailleClair), humanSize(haut), surcout, humanSize(bas), humanSize(haut))
}

// padRegle dit ce que le profil garantit, indépendamment d'un fichier donné.
func padRegle(p pkg.PadProfile) string {
	switch p {
	case pkg.PadFort:
		return "palier deux fois plus large, surcoût plafonné à ~25 %"
	case pkg.PadMaximum:
		return "tous les fichiers d'une octave sortent à la même taille, jusqu'à +100 %"
	default:
		return "surcoût plafonné à ~12 %"
	}
}

// metaEncodee traduit la réponse de la TUI en mode de métadonnées.
func metaEncodee(garder bool) pkg.MetadataMode {
	if garder {
		return pkg.MetadataMinimal
	}
	return pkg.MetadataNone
}

// lireEnTete lit l'en-tête d'un .chto, en le disant dans le cadre plutôt que
// de le laisser vide le temps de la lecture.
func lireEnTete(path string) (pkg.Details, error) {
	var d pkg.Details
	err := enCours("en-tête", "lecture de l'en-tête…", func() error {
		var err error
		d, err = pkg.Inspect(path)
		return err
	})
	return d, err
}

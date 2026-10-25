//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"chiffremento-cli/pkg"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
	"golang.org/x/term"
)

// Parcours de bout en bout de l'interface guidée : le vrai binaire, lancé sans
// argument dans un pseudo-terminal, piloté au clavier comme par un humain.
//
// Toute la connaissance de l'interface — touches, libellés, ordre des écrans —
// vit dans les méthodes du pilote. Les tests TestE2E* ne disent que l'intention
// (« chiffrer ce fichier avec cette phrase ») : quand l'interface changera de
// visage, seules ces méthodes seront à réécrire.

const (
	// delaiEcran borne l'attente d'un texte à l'écran. Large : un écran peut
	// suivre une dérivation Argon2 et l'écran de progression, qui dure au moins
	// 4 s par choix esthétique (progress.go).
	delaiEcran = 20 * time.Second
	// delaiSortie borne l'attente de la fin du processus.
	delaiSortie = 60 * time.Second
	// delaiNettoyage borne chaque attente du nettoyage : un processus tué ou
	// une lecture qui ne rend pas la main ne doivent pas bloquer la suite.
	delaiNettoyage = 5 * time.Second
	// calmeSortie et delaiDerniersOctets règlent la dernière lecture, une fois
	// le processus sorti : on relit jusqu'à ce que la sortie cesse de grossir
	// pendant calmeSortie, sans dépasser delaiDerniersOctets.
	calmeSortie         = 200 * time.Millisecond
	delaiDerniersOctets = 2 * time.Second
	// pasDeSondage est la pause entre deux relectures de l'écran : assez courte
	// pour ne pas ralentir les tests, assez longue pour ne pas occuper le CPU.
	pasDeSondage = 20 * time.Millisecond
)

// Séquences que le terminal enverrait pour chaque touche.
const (
	toucheHaut   = "\x1b[A"
	toucheBas    = "\x1b[B"
	toucheEntree = "\r"
	toucheCtrlC  = "\x03"
)

// Repères de l'écran. huh dessine une barre « ┃ » devant le champ qui a le
// focus, et un « > » devant l'option sous le curseur. Attendre « ┃ titre » ou
// « > option » après une touche, c'est attendre que l'interface l'ait traitée :
// c'est ce qui synchronise le pilote, plutôt qu'une pause à l'aveugle.
//
// La synchronisation compte parce que huh passe au champ suivant par un message
// asynchrone : une touche envoyée trop tôt serait lue par le champ qu'on croit
// avoir quitté.
const (
	focus   = "┃ "
	curseur = "> "
)

// Requêtes que bubbletea et lipgloss adressent au terminal au démarrage, et
// réponses d'un terminal ordinaire. Le programme attend ces réponses avant de
// dessiner son premier écran : sans elles, il reste muet.
var reponsesTerminal = []struct{ requete, reponse string }{
	{"\x1b]11;?\x1b\\", "\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\"}, // OSC 11 : couleur de fond
	{"\x1b[6n", "\x1b[1;1R"},                                // DSR : position du curseur
}

// pilote tient un chiffremento lancé dans un pseudo-terminal.
type pilote struct {
	t       *testing.T
	maitre  *os.File
	esclave *os.File
	cmd     *exec.Cmd
	etatTTY *term.State // état du terminal avant le lancement

	mu       sync.Mutex
	sortie   []byte // tout ce que le programme a écrit
	repondus []int  // requêtes déjà servies, par entrée de reponsesTerminal
	lu       int    // position, dans la sortie nettoyée, de la dernière attente satisfaite

	fini chan struct{} // fermé quand le processus est terminé
	err  error         // résultat de cmd.Wait, lisible après fini

	action string // dernière opération choisie, pour reconnaître l'écran suivant
	menuVu bool   // le menu est à l'écran, et aucune touche n'est partie depuis
}

// lancerPilote démarre le binaire de test comme un chiffremento sans argument,
// dans dossier, sur un pseudo-terminal de 100×40.
//
// L'esclave est ouvert ici et reste ouvert jusqu'au nettoyage, plutôt que
// confié à pty.StartWithSize qui le referme aussitôt : sur macOS, un esclave
// refermé côté parent rend muettes les écritures suivantes (voir
// TestReadPasswordDepuisTTY), et il sert aussi à relire l'état du terminal
// après la sortie du programme.
func lancerPilote(t *testing.T, dossier string) *pilote {
	t.Helper()
	maitre, esclave, err := pty.Open()
	if err != nil {
		t.Skipf("pseudo-terminal indisponible ici: %v", err)
	}
	if err := pty.Setsize(maitre, &pty.Winsize{Cols: 100, Rows: 40}); err != nil {
		maitre.Close()
		esclave.Close()
		t.Fatal(err)
	}
	etat, err := term.GetState(int(esclave.Fd()))
	if err != nil {
		maitre.Close()
		esclave.Close()
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0])
	// L'environnement complet est transmis : go test -cover y pose GOCOVERDIR,
	// et c'est par lui que les compteurs de l'enfant rejoignent la mesure.
	cmd.Env = append(os.Environ(), "CHIFFREMENTO_E2E_MAIN=1", "TERM=xterm-256color")
	cmd.Dir = dossier
	cmd.Stdin, cmd.Stdout, cmd.Stderr = esclave, esclave, esclave
	// Une session neuve, détachée du terminal qui lance go test : rien de ce
	// que fait l'enfant ne doit atteindre celui du développeur. Le pty n'en
	// devient pas pour autant le terminal de contrôle (pas de Setctty) : sur
	// macOS, la sortie d'un chef de session révoque son terminal de contrôle,
	// et l'esclave ne répondrait plus quand terminalRestaure vient relire ses
	// réglages. L'interface n'en a pas besoin : elle lit et écrit sur ses
	// descripteurs standard.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		maitre.Close()
		esclave.Close()
		t.Fatal(err)
	}

	p := &pilote{
		t: t, maitre: maitre, esclave: esclave, cmd: cmd, etatTTY: etat,
		repondus: make([]int, len(reponsesTerminal)),
		fini:     make(chan struct{}),
	}
	go func() {
		p.err = cmd.Wait()
		close(p.fini)
	}()
	lectureFinie := make(chan struct{})
	go p.lire(lectureFinie)

	t.Cleanup(func() {
		select {
		case <-p.fini:
		default:
			// Le test a échoué en route : on ne laisse pas un processus orphelin.
			_ = cmd.Process.Kill()
			select {
			case <-p.fini:
			case <-time.After(delaiNettoyage):
				t.Logf("le processus %d n'a pas fini %v après avoir été tué", cmd.Process.Pid, delaiNettoyage)
			}
		}
		maitre.Close()
		esclave.Close()
		select {
		case <-lectureFinie:
		case <-time.After(delaiNettoyage):
			t.Logf("la lecture du terminal n'a pas rendu la main %v après sa fermeture", delaiNettoyage)
		}
	})
	return p
}

// lire recueille la sortie en continu et joue le rôle du terminal : chaque
// requête vue reçoit sa réponse, jamais avant d'avoir été vue — une réponse
// anticipée ne serait pas lue.
func (p *pilote) lire(fin chan<- struct{}) {
	defer close(fin)
	tampon := make([]byte, 32*1024)
	for {
		n, err := p.maitre.Read(tampon)
		if n > 0 {
			p.mu.Lock()
			p.sortie = append(p.sortie, tampon[:n]...)
			var aEnvoyer []string
			for i, r := range reponsesTerminal {
				vues := bytes.Count(p.sortie, []byte(r.requete))
				for ; p.repondus[i] < vues; p.repondus[i]++ {
					aEnvoyer = append(aEnvoyer, r.reponse)
				}
			}
			p.mu.Unlock()
			for _, r := range aEnvoyer {
				_, _ = p.maitre.WriteString(r)
			}
		}
		if err != nil {
			return
		}
	}
}

// ecran rend la sortie débarrassée de ses séquences de contrôle.
func (p *pilote) ecran() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ansi.Strip(string(p.sortie))
}

// queue rend la fin de l'écran, pour les messages d'échec.
//
// Sous go test -race, l'enfant est lui aussi instrumenté : une course y fait
// sortir le programme en 66 et son rapport se perd au milieu de l'interface.
// C'est alors ce rapport qu'on rend, la fin de l'écran n'expliquant rien.
func (p *pilote) queue() string {
	e := p.ecran()
	if i := strings.Index(e, "WARNING: DATA RACE"); i >= 0 {
		return e[i:]
	}
	const garde = 3000
	if len(e) > garde {
		e = e[len(e)-garde:]
	}
	return e
}

// attendre attend que texte apparaisse après la dernière attente satisfaite.
// Chercher plus loin que la précédente évite de prendre pour le nouvel écran
// un libellé resté affiché par l'ancien.
func (p *pilote) attendre(texte string) {
	p.t.Helper()
	limite := time.Now().Add(delaiEcran)
	for {
		e := p.ecran()
		if i := strings.Index(e[p.lu:], texte); i >= 0 {
			p.lu += i + len(texte)
			return
		}
		select {
		case <-p.fini:
			// Le processus est parti : le texte n'arrivera plus, mais ses
			// derniers octets peuvent encore être en route dans le pty.
			p.attendreFinDeSortie()
			if e := p.ecran(); strings.Contains(e[p.lu:], texte) {
				p.lu += strings.Index(e[p.lu:], texte) + len(texte)
				return
			}
			p.t.Fatalf("le programme est sorti (%v) sans afficher %q ; fin de l'écran :\n%s", p.err, texte, p.queue())
		default:
		}
		if time.Now().After(limite) {
			p.t.Fatalf("%q n'est pas apparu en %v ; fin de l'écran :\n%s", texte, delaiEcran, p.queue())
		}
		time.Sleep(pasDeSondage)
	}
}

// taille rend le nombre d'octets reçus jusqu'ici.
func (p *pilote) taille() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sortie)
}

// attendreFinDeSortie relit jusqu'à ce que la sortie cesse de grossir pendant
// calmeSortie, sans dépasser delaiDerniersOctets.
func (p *pilote) attendreFinDeSortie() {
	limite := time.Now().Add(delaiDerniersOctets)
	vue, depuis := p.taille(), time.Now()
	for time.Now().Before(limite) && time.Since(depuis) < calmeSortie {
		time.Sleep(pasDeSondage)
		if n := p.taille(); n != vue {
			vue, depuis = n, time.Now()
		}
	}
}

// touches envoie des octets au programme, comme un clavier. Aucune pause : la
// méthode qui appelle attend ensuite le repère d'écran qui prouve que la touche
// a été traitée.
func (p *pilote) touches(seq string) {
	p.t.Helper()
	p.menuVu = false
	if _, err := p.maitre.WriteString(seq); err != nil {
		p.t.Fatalf("écriture sur le terminal: %v", err)
	}
}

// taper saisit du texte puis le valide. Texte et entrée partent ensemble sans
// risque : ils visent le même champ, et bubbletea traite les touches dans
// l'ordre.
func (p *pilote) taper(texte string) {
	p.t.Helper()
	p.touches(texte + toucheEntree)
}

// valider appuie sur entrée, puis attend que le focus soit passé au champ
// suivant, désigné par son titre.
func (p *pilote) valider(titreSuivant string) {
	p.t.Helper()
	p.touches(toucheEntree)
	p.attendre(focus + titreSuivant)
}

// attendreProgression attend l'écran de progression de l'opération. Il dure
// au moins 4 s (progress.go) : il reste affiché le temps d'y envoyer une touche.
func (p *pilote) attendreProgression() {
	p.t.Helper()
	p.attendre("aead")
}

// attendreTemporaire attend qu'un fichier temporaire d'écriture
// (« .chto-tmp-* », créé dans le dossier de la cible) apparaisse dans dossier :
// l'opération a alors dépassé la dérivation de clé et écrit pour de bon. Échoue
// si le processus se termine avant, ou après delaiEcran.
func (p *pilote) attendreTemporaire(dossier string) {
	p.t.Helper()
	limite := time.Now().Add(delaiEcran)
	for {
		temporaires, err := filepath.Glob(filepath.Join(dossier, ".chto-tmp-*"))
		if err != nil {
			p.t.Fatal(err)
		}
		if len(temporaires) > 0 {
			return
		}
		select {
		case <-p.fini:
			p.t.Fatalf("le processus s'est terminé sans qu'un temporaire n'apparaisse ; fin de l'écran :\n%s", p.queue())
		default:
		}
		if time.Now().After(limite) {
			p.t.Fatalf("aucun temporaire en %v ; fin de l'écran :\n%s", delaiEcran, p.queue())
		}
		time.Sleep(pasDeSondage)
	}
}

// attendrePremierEcran attend que le choix de l'opération soit affiché en
// entier.
func (p *pilote) attendrePremierEcran() {
	p.t.Helper()
	p.attendre("désigner la cible")
}

// choisirAction choisit l'opération au premier écran, puis la saisie du chemin
// au clavier.
func (p *pilote) choisirAction(action string) {
	p.t.Helper()
	// Les options dans l'ordre de l'écran, jusqu'à celle voulue : chacune est
	// le repère du « ↓ » qui l'atteint.
	options := map[string][]string{
		"chiffrer":   nil,
		"déchiffrer": {"déchiffrer un .chto"},
		"vérifier":   {"déchiffrer un .chto", "vérifier un .chto"},
		"changer le mot de passe": {
			"déchiffrer un .chto", "vérifier un .chto", "changer le mot de passe d'un .chto",
		},
	}
	chemin, ok := options[action]
	if !ok {
		p.t.Fatalf("action inconnue du pilote : %q", action)
	}
	p.attendrePremierEcran()
	for _, option := range chemin {
		p.touches(toucheBas)
		p.attendre(curseur + option)
	}
	p.valider("désigner la cible") // valide l'opération
	// Valide « saisir un chemin », proposé par défaut. L'écran se ferme : le
	// repère est le titre de l'écran suivant, attendu par saisirChemin.
	p.touches(toucheEntree)
	p.action = action
}

// saisirChemin remplit le champ de la cible.
func (p *pilote) saisirChemin(chemin string) {
	p.t.Helper()
	switch p.action {
	case "chiffrer":
		p.attendre("fichier ou dossier à chiffrer")
	case "changer le mot de passe":
		p.attendre(".chto dont changer le mot de passe")
	default:
		p.attendre(".chto à lire")
	}
	p.taper(chemin)
}

// changerPhrase remplit l'écran du changement de mot de passe : l'actuel, le
// nouveau, puis sa confirmation, chaque saisie attendant que son champ ait le
// focus.
func (p *pilote) changerPhrase(actuelle, nouvelle string) {
	p.t.Helper()
	p.attendre(focus + "mot de passe actuel")
	p.taper(actuelle)
	p.attendre(focus + "nouveau mot de passe")
	p.taper(nouvelle)
	p.attendre(focus + "confirmation")
	p.taper(nouvelle)
}

// validerOptionsParDefaut accepte une à une les options de chiffrement
// proposées pour un fichier : algorithme, coût de la dérivation, compression,
// masquage de la taille, conservation du nom, puis « le saisir moi-même » pour
// le mot de passe.
func (p *pilote) validerOptionsParDefaut() {
	p.t.Helper()
	p.attendre(focus + "algorithme")
	p.valider("coût de la dérivation de clé")
	p.valider("compresser avant chiffrement")
	p.valider("masquer la taille réelle")
	p.valider("conserver le nom et la date d'origine")
	p.valider("mot de passe") // générer une phrase, ou la saisir
	p.attendre(curseur + "le saisir moi-même")
	// Valide « le saisir moi-même » : le repère du champ de saisie est attendu
	// par saisirPhrase ou commencerPhrase.
	p.touches(toucheEntree)
}

// attendreChampPhrase attend que le champ de la phrase ait le focus.
//
// Au chiffrement, le repère est « confirmation », qui s'affiche avec le champ
// du mot de passe : celui-ci apparaît à la ligne où se tenait la question
// « mot de passe » (générer ou saisir), et bubbletea ne réécrit pas une ligne
// inchangée — son titre ne repasse donc pas dans le flux.
func (p *pilote) attendreChampPhrase() {
	p.t.Helper()
	if p.action == "chiffrer" {
		p.attendre("confirmation")
		return
	}
	p.attendre(focus + "mot de passe")
}

// saisirPhrase tape la phrase de passe ; confirmer la tape une seconde fois,
// comme le demande le chiffrement.
func (p *pilote) saisirPhrase(phrase string, confirmer bool) {
	p.t.Helper()
	p.attendreChampPhrase()
	p.taper(phrase)
	if confirmer {
		p.attendre(focus + "confirmation")
		p.taper(phrase)
	}
}

// commencerPhrase tape le début d'une phrase sans la valider : c'est là qu'un
// abandon en cours de saisie se teste.
func (p *pilote) commencerPhrase(debut string) {
	p.t.Helper()
	p.attendreChampPhrase()
	p.touches(debut)
}

// repondreSuppression répond à la question posée après l'opération : effacer
// l'original (chiffrement) ou le chiffré (déchiffrement). « garder » est sous
// le curseur ; « supprimer » est juste au-dessus.
func (p *pilote) repondreSuppression(supprimer bool) {
	p.t.Helper()
	p.attendre(curseur + "garder")
	if supprimer {
		p.touches(toucheHaut)
		p.attendre(curseur + "supprimer")
	}
	p.touches(toucheEntree)
}

// repondreGarder répond à la question posée après une opération réussie avec
// une phrase tapée : la garder pour la session ou non. « ne pas la garder »
// est sous le curseur ; « la garder » est juste au-dessus.
func (p *pilote) repondreGarder(garder bool) {
	p.t.Helper()
	p.attendre(curseur + "ne pas la garder")
	if garder {
		p.touches(toucheHaut)
		p.attendre(curseur + "la garder")
	}
	p.touches(toucheEntree)
}

// accepterPhraseEnMemoire valide « utiliser la phrase en mémoire », proposé
// par défaut à la place du champ du mot de passe.
func (p *pilote) accepterPhraseEnMemoire() {
	p.t.Helper()
	p.attendre(curseur + "utiliser la phrase en mémoire")
	p.touches(toucheEntree)
}

// attendreSuccesVerification attend le message de fin d'une vérification
// réussie d'un fichier.
func (p *pilote) attendreSuccesVerification() {
	p.t.Helper()
	p.attendre(verifySucces(false))
}

// attendreRefusMotDePasse attend l'annonce d'une mauvaise phrase de passe,
// affichée dans le cadre, puis revient au menu.
func (p *pilote) attendreRefusMotDePasse() {
	p.t.Helper()
	p.attendre(pkg.ErrBadPassword.Error())
	p.revenirAuMenu()
}

// revenirAuMenu referme la carte résultat ou l'écran d'erreur par ⏎. Le
// repère est la barre du bas, propre à ces deux écrans : le ✓ peut occuper
// la même ligne que sur la question d'avant, et bubbletea ne réécrit pas une
// ligne inchangée. La touche part après le repère : sans écran ouvert, l'hôte
// la jetterait.
func (p *pilote) revenirAuMenu() {
	p.t.Helper()
	p.attendre(touchesResultat)
	p.touches(toucheEntree)
}

// apresEcranAlternatif rend, débarrassé des séquences de contrôle, ce que le
// programme a écrit après avoir quitté l'écran alternatif pour la dernière
// fois : les résumés de la session.
func (p *pilote) apresEcranAlternatif() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	brut := string(p.sortie)
	i := strings.LastIndex(brut, "\x1b[?1049l")
	if i < 0 {
		return ""
	}
	return ansi.Strip(brut[i:])
}

// abandonnerParCtrlC appuie sur Ctrl+C. En mode brut, c'est une touche et non
// un signal : c'est bien l'interface qui doit la traiter.
func (p *pilote) abandonnerParCtrlC() {
	p.t.Helper()
	p.touches(toucheCtrlC)
}

// chiffreAnnonceUneFois vérifie, une fois le processus sorti, que le
// terminal ordinaire annonce nom par un ✓, exactement une fois : soit le ✓
// ordinaire, soit la mention « écrit avant l'interruption », jamais les deux
// ni aucun.
func (p *pilote) chiffreAnnonceUneFois(nom string) {
	p.t.Helper()
	p.attendreFinDeSortie()
	apres := p.apresEcranAlternatif()
	if n := strings.Count(apres, "✓  "+nom); n != 1 {
		p.t.Fatalf("%q annoncé %d fois après l'écran alternatif, attendu 1 : %q", nom, n, apres)
	}
}

// raccrocher envoie SIGHUP au programme, comme la fermeture de la fenêtre du
// terminal. L'enfant est dans sa propre session (Setsid) : fermer le pty ne
// le lui enverrait pas.
func (p *pilote) raccrocher() {
	p.t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		p.t.Fatal(err)
	}
}

// attendreMenu attend le retour au menu après une opération.
func (p *pilote) attendreMenu() {
	p.t.Helper()
	p.attendre("désigner la cible")
	p.menuVu = true
}

// quitter quitte la session depuis le menu, par la touche q, une fois le
// menu revenu.
func (p *pilote) quitter() {
	p.t.Helper()
	if !p.menuVu {
		p.attendreMenu()
	}
	p.touches("q")
}

// codeDeSortie attend que le programme se termine de lui-même et rend son code.
// Le laisser sortir seul compte : un processus tué n'écrit pas ses compteurs
// de couverture.
func (p *pilote) codeDeSortie() int {
	p.t.Helper()
	select {
	case <-p.fini:
	case <-time.After(delaiSortie):
		p.t.Fatalf("le programme ne s'est pas terminé en %v ; fin de l'écran :\n%s", delaiSortie, p.queue())
	}
	if p.err == nil {
		return 0
	}
	var sortie *exec.ExitError
	if errors.As(p.err, &sortie) {
		return sortie.ExitCode()
	}
	p.t.Fatalf("fin anormale du programme: %v", p.err)
	return -1
}

// terminalRestaure vérifie, une fois le programme sorti, que le terminal a
// retrouvé ses réglages d'origine (écho, mode ligne), que le curseur a été
// rendu visible après avoir été masqué, et que l'écran alternatif, ouvert par
// le plein écran, a été quitté.
func (p *pilote) terminalRestaure() {
	p.t.Helper()
	etat, err := term.GetState(int(p.esclave.Fd()))
	if err != nil {
		p.t.Fatal(err)
	}
	if !reflect.DeepEqual(etat, p.etatTTY) {
		p.t.Error("le terminal n'a pas retrouvé ses réglages d'origine (écho, mode ligne)")
	}
	p.mu.Lock()
	brut := string(p.sortie)
	p.mu.Unlock()
	const masque, montre = "\x1b[?25l", "\x1b[?25h"
	if strings.LastIndex(brut, masque) > strings.LastIndex(brut, montre) {
		p.t.Error("le curseur est resté masqué à la sortie")
	}
	const entreeAlt, sortieAlt = "\x1b[?1049h", "\x1b[?1049l"
	if strings.LastIndex(brut, entreeAlt) < 0 {
		p.t.Error("l'interface ne s'est pas ouverte en plein écran (écran alternatif)")
	}
	if strings.LastIndex(brut, entreeAlt) > strings.LastIndex(brut, sortieAlt) {
		p.t.Error("l'écran alternatif n'a pas été quitté à la sortie")
	}
}

// ecranAlternatifQuitte dit si le programme a déjà quitté l'écran alternatif
// une fois au moins.
func (p *pilote) ecranAlternatifQuitte() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Contains(p.sortie, []byte("\x1b[?1049l"))
}

// contenuDossier liste les noms présents dans dossier, triés.
func contenuDossier(t *testing.T, dossier string) []string {
	t.Helper()
	entrees, err := os.ReadDir(dossier)
	if err != nil {
		t.Fatal(err)
	}
	noms := make([]string, 0, len(entrees))
	for _, e := range entrees {
		noms = append(noms, e.Name())
	}
	slices.Sort(noms)
	return noms
}

// ecrireFichier pose un fichier de test.
func ecrireFichier(t *testing.T, chemin string, contenu []byte) {
	t.Helper()
	if err := os.WriteFile(chemin, contenu, 0o600); err != nil {
		t.Fatal(err)
	}
}

// R-TUI-01, R-TUI-02 et R-TUI-11 : un fichier chiffré par l'interface se
// déchiffre par l'interface, à l'octet près, dans la même session : le menu
// revient après chaque opération, et quitter sort en code 0.
func TestE2EChiffrerPuisDechiffrer(t *testing.T) {
	dossier := t.TempDir()
	original := []byte("données confidentielles\n")
	ecrireFichier(t, filepath.Join(dossier, "secret.txt"), original)

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("secret.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("correct horse battery staple", true)
	p.repondreSuppression(false)
	p.repondreGarder(false)
	p.revenirAuMenu()
	if _, err := os.Stat(filepath.Join(dossier, "secret.txt.chto")); err != nil {
		t.Fatalf("aucun chiffré produit : %v", err)
	}

	// L'original retiré pendant que la session continue : le déchiffrement
	// n'a pas à demander s'il faut l'écraser.
	if err := os.Remove(filepath.Join(dossier, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	p.choisirAction("déchiffrer")
	p.saisirChemin("secret.txt.chto")
	p.saisirPhrase("correct horse battery staple", false)
	p.repondreSuppression(false)
	p.repondreGarder(false)
	p.revenirAuMenu()
	p.quitter()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("session : code %d ; fin de l'écran :\n%s", code, p.queue())
	}
	p.terminalRestaure()
	obtenu, err := os.ReadFile(filepath.Join(dossier, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obtenu, original) {
		t.Fatalf("contenu déchiffré différent : %q", obtenu)
	}
}

// R-TUI-12 : la phrase gardée après le chiffrement est proposée au
// déchiffrement suivant ; l'accepter suffit à restituer le contenu, sans
// rien retaper, et la question de la garder n'est pas reposée.
func TestE2EPhraseGardeePourLaSession(t *testing.T) {
	dossier := t.TempDir()
	original := []byte("données confidentielles\n")
	ecrireFichier(t, filepath.Join(dossier, "secret.txt"), original)

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("secret.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("correct horse battery staple", true)
	p.repondreSuppression(false)
	p.repondreGarder(true)
	p.attendre("● phrase en mémoire")
	p.revenirAuMenu()

	if err := os.Remove(filepath.Join(dossier, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	p.choisirAction("déchiffrer")
	p.saisirChemin("secret.txt.chto")
	p.accepterPhraseEnMemoire()
	p.repondreSuppression(false)
	p.revenirAuMenu()
	p.quitter()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("session : code %d ; fin de l'écran :\n%s", code, p.queue())
	}
	p.terminalRestaure()
	obtenu, err := os.ReadFile(filepath.Join(dossier, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obtenu, original) {
		t.Fatalf("contenu déchiffré différent : %q", obtenu)
	}
}

// R-TUI-12 et R-TUI-04 : Ctrl+C avec une phrase gardée sort en 130 et rend
// le terminal, comme sans phrase. L'effacement lui-même (octets à zéro avant
// la sortie) se vérifie dans le processus : TestPhraseOublieeALaSortie.
func TestE2ECtrlCAvecPhraseGardee(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "secret.txt"), []byte("données\n"))

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("secret.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("correct horse battery staple", true)
	p.repondreSuppression(false)
	p.repondreGarder(true)
	p.attendre("● phrase en mémoire")
	p.revenirAuMenu()
	p.attendreMenu()
	p.abandonnerParCtrlC()
	if code := p.codeDeSortie(); code != exitInterrompu {
		t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
	}
	p.terminalRestaure()
	if strings.Contains(p.ecran(), "erreur :") {
		t.Errorf("Ctrl+C avec une phrase gardée affiche une erreur ; fin de l'écran :\n%s", p.queue())
	}
}

// chiffrerPourTest prépare un .chto hors de l'interface, au profil standard.
func chiffrerPourTest(t *testing.T, clair, chiffre, phrase string) {
	t.Helper()
	err := pkg.Encrypt(clair, chiffre, []byte(phrase), pkg.Options{Algo: pkg.AlgoAES, KDF: pkg.KDFStandard})
	if err != nil {
		t.Fatal(err)
	}
}

// R-TUI-03 : la vérification conclut au succès et n'écrit rien.
func TestE2EVerifier(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "notes.txt"), []byte("à contrôler\n"))
	chiffrerPourTest(t, filepath.Join(dossier, "notes.txt"), filepath.Join(dossier, "notes.txt.chto"), "phrase de controle")
	if err := os.Remove(filepath.Join(dossier, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	avant := contenuDossier(t, dossier)

	p := lancerPilote(t, dossier)
	p.choisirAction("vérifier")
	p.saisirChemin("notes.txt.chto")
	p.saisirPhrase("phrase de controle", false)
	// Le ✓ s'affiche dans la carte résultat, avant le retour au menu.
	p.attendreSuccesVerification()
	p.repondreGarder(false)
	p.revenirAuMenu()
	p.quitter()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("vérification : code %d ; fin de l'écran :\n%s", code, p.queue())
	}
	if apres := contenuDossier(t, dossier); !slices.Equal(avant, apres) {
		t.Fatalf("la vérification a écrit sur le disque : %v puis %v", avant, apres)
	}
}

// R-TUI-05 et R-TUI-11 : une mauvaise phrase est annoncée clairement, aucun
// clair n'est écrit, la session revient au menu, et quitter sort en code 1.
func TestE2EMauvaisePhrase(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "notes.txt"), []byte("contenu\n"))
	chiffrerPourTest(t, filepath.Join(dossier, "notes.txt"), filepath.Join(dossier, "notes.txt.chto"), "la bonne phrase")
	if err := os.Remove(filepath.Join(dossier, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	avant := contenuDossier(t, dossier)

	p := lancerPilote(t, dossier)
	p.choisirAction("déchiffrer")
	p.saisirChemin("notes.txt.chto")
	p.saisirPhrase("une autre phrase", false)
	p.attendreRefusMotDePasse()
	p.quitter()
	if code := p.codeDeSortie(); code != 1 {
		t.Fatalf("mauvaise phrase : code %d, attendu 1", code)
	}
	p.terminalRestaure()
	if apres := contenuDossier(t, dossier); !slices.Equal(avant, apres) {
		t.Fatalf("un fichier a été écrit malgré la mauvaise phrase : %v puis %v", avant, apres)
	}
}

// R-TUI-04, R-CLI-08 et R-FS-02 : Ctrl+C sort en 130, sans message d'erreur,
// rend le terminal tel qu'il était et, avant le lancement de l'opération,
// n'écrit rien.
//
// L'abandon a lieu avant toute écriture ; l'abandon pendant l'opération est
// couvert par TestE2EInterruptionPendantOperation.
func TestE2EInterruption(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "secret.txt"), []byte("à ne pas toucher\n"))
	avant := contenuDossier(t, dossier)

	t.Run("ctrl+c au premier écran", func(t *testing.T) {
		p := lancerPilote(t, dossier)
		p.attendrePremierEcran()
		p.abandonnerParCtrlC()
		if code := p.codeDeSortie(); code != exitInterrompu {
			t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
		}
		p.terminalRestaure()
		if strings.Contains(p.ecran(), "erreur :") {
			t.Errorf("un abandon volontaire ne doit afficher aucune erreur ; fin de l'écran :\n%s", p.queue())
		}
	})

	t.Run("ctrl+c pendant la phrase", func(t *testing.T) {
		p := lancerPilote(t, dossier)
		p.choisirAction("chiffrer")
		p.saisirChemin("secret.txt")
		p.validerOptionsParDefaut()
		p.commencerPhrase("correct horse") // saisie entamée, pas validée
		p.abandonnerParCtrlC()
		if code := p.codeDeSortie(); code != exitInterrompu {
			t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
		}
		p.terminalRestaure()
		if strings.Contains(p.ecran(), "erreur :") {
			t.Errorf("un abandon volontaire ne doit afficher aucune erreur ; fin de l'écran :\n%s", p.queue())
		}
	})

	if apres := contenuDossier(t, dossier); !slices.Equal(avant, apres) {
		t.Fatalf("l'abandon a laissé des traces : %v puis %v", avant, apres)
	}
}

// R-TUI-04 et R-FS-02 : un abandon par Ctrl+C pendant l'écriture, écran de
// progression affiché et temporaire déjà créé sur le disque, sort en 130, rend
// le terminal, garde l'original intact et supprime le temporaire sans laisser
// de chiffré.
func TestE2EInterruptionPendantOperation(t *testing.T) {
	dossier := t.TempDir()
	// Assez gros pour que l'opération soit en cours à l'arrivée de Ctrl+C.
	original := bytes.Repeat([]byte("contenu à protéger 0123456789\n"), 2<<20)
	ecrireFichier(t, filepath.Join(dossier, "gros.bin"), original)
	avant := contenuDossier(t, dossier)

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("gros.bin")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase d'abandon", true)
	p.attendreProgression()
	p.attendreTemporaire(dossier)
	// La progression s'affiche dans le cadre de l'hôte : l'écran alternatif
	// n'a pas été quitté pour la montrer (le terminal n'est pas prêté).
	if p.ecranAlternatifQuitte() {
		t.Error("l'écran alternatif a été quitté pour afficher la progression")
	}
	p.abandonnerParCtrlC()

	if code := p.codeDeSortie(); code != exitInterrompu {
		t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
	}
	p.terminalRestaure()
	if apres := contenuDossier(t, dossier); !slices.Equal(avant, apres) {
		t.Fatalf("l'abandon a laissé des traces : %v puis %v", avant, apres)
	}
	obtenu, err := os.ReadFile(filepath.Join(dossier, "gros.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obtenu, original) {
		t.Fatal("l'original a été modifié par l'abandon")
	}
}

// R-FS-02 : Ctrl+C pendant l'extraction d'un dossier (beaucoup de petits
// fichiers) sort en 130 sans laisser de .chto-tmp-* nulle part — l'extraction
// recréait le dossier temporaire supprimé et y écrivait du clair — ni de
// destination, et sans toucher au .chto. SIGHUP (fenêtre du terminal fermée)
// fait de même, et sort en 129 : avant, le processus mourait sur-le-champ en
// laissant le clair déjà extrait.
func TestE2EInterruptionPendantExtraction(t *testing.T) {
	cas := []struct {
		nom      string
		abandon  func(p *pilote)
		code     int
		terminal bool // le terminal est encore là pour être vérifié
	}{
		{"ctrl+c", (*pilote).abandonnerParCtrlC, exitInterrompu, true},
		{"sighup", (*pilote).raccrocher, exitRaccroche, false},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			interrompreUneExtraction(t, c.abandon, c.code, c.terminal)
		})
	}
}

// interrompreUneExtraction lance l'extraction d'un dossier de 20 000
// fichiers dans l'interface, l'abandonne par abandon une fois le temporaire
// créé, puis vérifie le code de sortie et qu'il ne reste rien.
func interrompreUneExtraction(t *testing.T, abandon func(p *pilote), code int, verifierTerminal bool) {
	ext := preparerExtractionLongue(t)
	p := lancerPilote(t, ext.dossier)
	p.choisirAction("déchiffrer")
	p.saisirChemin("archive.chto")
	p.saisirPhrase(ext.phrase, false)
	p.attendreProgression()
	p.attendreTemporaire(ext.dossier)
	abandon(p)

	if obtenu := p.codeDeSortie(); obtenu != code {
		t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", obtenu, code, p.queue())
	}
	if verifierTerminal {
		p.terminalRestaure()
	}
	ext.rienNeReste(t)
}

// R-FS-02 : en mode -mode, SIGHUP pendant l'extraction d'un dossier sort en
// 129 sans laisser de temporaire ni de destination, comme Ctrl+C (130).
func TestCLIRaccrochePendantExtraction(t *testing.T) {
	ext := preparerExtractionLongue(t)
	cmd := exec.Command(os.Args[0], "-mode", "dec", "-in", "archive.chto")
	cmd.Env = append(os.Environ(), "CHIFFREMENTO_E2E_MAIN=1")
	cmd.Dir = ext.dossier
	cmd.Stdin = strings.NewReader(ext.phrase + "\n")
	var sortie bytes.Buffer
	cmd.Stdout, cmd.Stderr = &sortie, &sortie
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fini := make(chan error, 1)
	go func() { fini <- cmd.Wait() }()

	limite := time.Now().Add(delaiEcran)
	for {
		temporaires, err := filepath.Glob(filepath.Join(ext.dossier, ".chto-tmp-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(temporaires) > 0 {
			break
		}
		if time.Now().After(limite) {
			_ = cmd.Process.Kill()
			t.Fatalf("aucun temporaire en %v ; sortie :\n%s", delaiEcran, sortie.String())
		}
		time.Sleep(pasDeSondage)
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	var err error
	select {
	case err = <-fini:
	case <-time.After(delaiSortie):
		_ = cmd.Process.Kill()
		t.Fatal("le programme ne s'est pas terminé après SIGHUP")
	}
	var fin *exec.ExitError
	if !errors.As(err, &fin) || fin.ExitCode() != exitRaccroche {
		t.Fatalf("fin = %v, attendu le code %d", err, exitRaccroche)
	}
	ext.rienNeReste(t)
}

// extractionLongue : un dossier de 20 000 petits fichiers chiffré, la source
// supprimée — assez long à extraire pour qu'un abandon tombe au milieu.
type extractionLongue struct {
	dossier, source, chiffre, phrase string
	avant                            []byte
}

func preparerExtractionLongue(t *testing.T) extractionLongue {
	t.Helper()
	dossier := t.TempDir()
	ext := extractionLongue{
		dossier: dossier,
		source:  filepath.Join(dossier, "archive"),
		chiffre: filepath.Join(dossier, "archive.chto"),
		phrase:  "phrase du dossier",
	}
	// Assez d'entrées pour que l'extraction soit en cours à l'arrivée de
	// l'abandon (~0,4 s pour 5 000 fichiers).
	const fichiers = 20000
	for i := range fichiers {
		sous := filepath.Join(ext.source, fmt.Sprintf("d%02d", i%20))
		if i < 20 {
			if err := os.MkdirAll(sous, 0700); err != nil {
				t.Fatal(err)
			}
		}
		ecrireFichier(t, filepath.Join(sous, fmt.Sprintf("f%05d.txt", i)), []byte("clair à ne pas laisser\n"))
	}
	chiffrerPourTest(t, ext.source, ext.chiffre, ext.phrase)
	if err := os.RemoveAll(ext.source); err != nil {
		t.Fatal(err)
	}
	avant, err := os.ReadFile(ext.chiffre)
	if err != nil {
		t.Fatal(err)
	}
	ext.avant = avant
	return ext
}

// rienNeReste vérifie qu'un abandon n'a laissé ni .chto-tmp-*, ni
// destination, et n'a pas touché au .chto.
func (ext extractionLongue) rienNeReste(t *testing.T) {
	t.Helper()
	err := filepath.WalkDir(ext.dossier, func(chemin string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(filepath.Base(chemin), ".chto-tmp-") {
			t.Errorf("temporaire resté après l'interruption : %s", chemin)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ext.source); !os.IsNotExist(err) {
		t.Errorf("la destination existe après l'interruption (Lstat : %v)", err)
	}
	apres, err := os.ReadFile(ext.chiffre)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ext.avant, apres) {
		t.Error("le .chto a été modifié par l'interruption")
	}
}

// R-TUI-04 et R-TUI-11 : Ctrl+C pendant une deuxième opération n'efface pas
// les résumés de la première, mis de côté pendant l'écran alternatif : ils
// s'impriment avant la sortie en 130.
func TestE2EInterruptionGardeLesResumes(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "premier.txt"), []byte("premier\n"))
	ecrireFichier(t, filepath.Join(dossier, "gros.bin"), bytes.Repeat([]byte("contenu à protéger 0123456789\n"), 2<<20))

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("premier.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase du premier", true)
	p.repondreSuppression(false)
	p.repondreGarder(false)
	p.revenirAuMenu()

	// choisirAction attend lui-même le retour du menu.
	p.choisirAction("chiffrer")
	p.saisirChemin("gros.bin")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase du second", true)
	p.attendreProgression()
	p.attendreTemporaire(dossier)
	p.abandonnerParCtrlC()
	if code := p.codeDeSortie(); code != exitInterrompu {
		t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
	}
	p.attendre("✓  premier.txt.chto")
	p.terminalRestaure()
}

// La suppression proposée après le chiffrement efface l'original, et le
// chiffré gardé se déchiffre.
func TestE2ESuppressionApresCoup(t *testing.T) {
	dossier := t.TempDir()
	original := []byte("à effacer après chiffrement\n")
	ecrireFichier(t, filepath.Join(dossier, "brouillon.txt"), original)

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("brouillon.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase de suppression", true)
	p.repondreSuppression(true)
	p.repondreGarder(false)
	p.revenirAuMenu()
	p.quitter()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("chiffrement : code %d ; fin de l'écran :\n%s", code, p.queue())
	}
	if _, err := os.Stat(filepath.Join(dossier, "brouillon.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("l'original est toujours là (%v)", err)
	}

	sortie := filepath.Join(t.TempDir(), "relu.txt")
	if err := pkg.Decrypt(filepath.Join(dossier, "brouillon.txt.chto"), sortie, []byte("phrase de suppression"), pkg.Options{}); err != nil {
		t.Fatalf("le chiffré gardé ne se déchiffre pas : %v", err)
	}
	obtenu, err := os.ReadFile(sortie)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obtenu, original) {
		t.Fatalf("contenu relu différent : %q", obtenu)
	}
}

// R-TUI-10 : le mot de passe changé depuis l'interface remplace l'ancien, et
// le contenu reste intact.
func TestE2EChangerMotDePasse(t *testing.T) {
	dossier := t.TempDir()
	original := []byte("contenu à garder\n")
	clair := filepath.Join(dossier, "coffre.txt")
	chiffre := clair + ".chto"
	ecrireFichier(t, clair, original)
	chiffrerPourTest(t, clair, chiffre, "ancienne phrase")
	if err := os.Remove(clair); err != nil {
		t.Fatal(err)
	}

	p := lancerPilote(t, dossier)
	p.choisirAction("changer le mot de passe")
	p.saisirChemin("coffre.txt.chto")
	p.changerPhrase("ancienne phrase", "nouvelle phrase de passe")
	p.attendre("mot de passe changé")
	p.revenirAuMenu()
	p.quitter()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("changement : code %d ; fin de l'écran :\n%s", code, p.queue())
	}

	sortie := filepath.Join(t.TempDir(), "relu.txt")
	if err := pkg.Decrypt(chiffre, sortie, []byte("ancienne phrase"), pkg.Options{}); !errors.Is(err, pkg.ErrBadPassword) {
		t.Fatalf("l'ancienne phrase devrait être refusée, erreur obtenue : %v", err)
	}
	if err := pkg.Decrypt(chiffre, sortie, []byte("nouvelle phrase de passe"), pkg.Options{}); err != nil {
		t.Fatalf("la nouvelle phrase ne déchiffre pas : %v", err)
	}
	obtenu, err := os.ReadFile(sortie)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obtenu, original) {
		t.Fatalf("contenu relu différent : %q", obtenu)
	}
}

// Les résumés affichés dans la carte sont réimprimés tels quels après la
// sortie de l'écran alternatif : le ✓ et le chemin produit restent dans le
// terminal une fois la session finie.
func TestResumesImprimesALaSortie(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "secret.txt"), []byte("à garder\n"))

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("secret.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase des résumés", true)
	p.repondreSuppression(false)
	p.repondreGarder(false)
	p.revenirAuMenu()
	p.quitter()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("code %d ; fin de l'écran :\n%s", code, p.queue())
	}
	p.attendreFinDeSortie()
	if apres := p.apresEcranAlternatif(); !strings.Contains(apres, "✓  secret.txt.chto") {
		t.Fatalf("le résumé n'est pas réimprimé après l'écran alternatif : %q", apres)
	}
}

// R-TUI-04 : Ctrl+C alors que le chiffré est déjà écrit sort en 130 ; les
// résumés imprimés à la sortie disent que le fichier existe.
//
// Sur une machine rapide, Ctrl+C tombe pendant la fin de l'animation et c'est
// la mention « écrit avant l'interruption » qui le dit. Sur une machine lente
// (Argon2 plus long que les 4 s de l'animation, runner macOS sous -race),
// l'écran s'est déjà fermé et c'est le ✓ ordinaire : les deux sont justes,
// et on ne peut pas choisir lequel sans une pause à l'aveugle. La mention
// elle-même est vérifiée sans pty par TestMentionEcritAvantInterruption.
func TestE2EInterruptionApresEcriture(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "petit.txt"), []byte("vite chiffré\n"))
	chiffre := filepath.Join(dossier, "petit.txt.chto")

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("petit.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase interrompue", true)
	p.attendreProgression()
	limite := time.Now().Add(delaiEcran)
	for {
		if _, err := os.Stat(chiffre); err == nil {
			break
		}
		if time.Now().After(limite) {
			t.Fatalf("aucun chiffré en %v ; fin de l'écran :\n%s", delaiEcran, p.queue())
		}
		time.Sleep(pasDeSondage)
	}
	p.abandonnerParCtrlC()
	if code := p.codeDeSortie(); code != exitInterrompu {
		t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
	}
	p.chiffreAnnonceUneFois("petit.txt.chto")
	p.terminalRestaure()
	if _, err := os.Stat(chiffre); err != nil {
		t.Fatalf("le chiffré annoncé n'existe pas : %v", err)
	}
}

// R-TUI-04, machine lente : quand Argon2 dure plus que les 4 s de l'animation
// (runner macOS sous -race), l'écran se ferme dès que l'opération rend la
// main, et Ctrl+C tombe sur la question de suppression. C'est l'état où le CI
// a échoué ; on l'atteint ici sans pause, en attendant la question. Le ✓
// ordinaire, déjà noté, suffit à dire que le fichier existe.
func TestE2EInterruptionSurQuestionSuppression(t *testing.T) {
	dossier := t.TempDir()
	ecrireFichier(t, filepath.Join(dossier, "petit.txt"), []byte("vite chiffré\n"))
	chiffre := filepath.Join(dossier, "petit.txt.chto")

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("petit.txt")
	p.validerOptionsParDefaut()
	p.saisirPhrase("phrase interrompue", true)
	p.attendre(curseur + "garder")
	p.abandonnerParCtrlC()
	if code := p.codeDeSortie(); code != exitInterrompu {
		t.Fatalf("code %d, attendu %d ; fin de l'écran :\n%s", code, exitInterrompu, p.queue())
	}
	p.chiffreAnnonceUneFois("petit.txt.chto")
	p.terminalRestaure()
	if _, err := os.Stat(chiffre); err != nil {
		t.Fatalf("le chiffré annoncé n'existe pas : %v", err)
	}
}

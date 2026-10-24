package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"chiffremento-cli/pkg"
)

// Menu persistant, Échap, quitter et code de sortie : le parcours de session
// tourne dans sa goroutine contre un hôte synchrone, comme en vrai, mais sans
// programme ni terminal. Le test joue la boucle de Bubble Tea.

// sessionDeTest tient un parcours de session lancé contre un hôte synchrone.
type sessionDeTest struct {
	t      *testing.T
	h      *hote
	boite  chan tea.Msg
	s      *session
	fini   chan struct{}
	quitte bool // le parcours a demandé la fin du programme
}

func lancerSessionDeTest(t *testing.T) *sessionDeTest {
	t.Helper()
	h, boite := hoteSynchrone(t, 100, 30)
	s := &session{}
	sessionCourante = s
	t.Cleanup(func() { sessionCourante = nil })
	st := &sessionDeTest{t: t, h: h, boite: boite, s: s, fini: make(chan struct{})}
	go func() {
		parcoursSession(h, s)
		close(st.fini)
	}()
	// Un parcours encore en vie à la fin du test serait bloqué dans afficher :
	// fermer l'hôte le libère.
	t.Cleanup(func() {
		h.fermer()
		select {
		case <-st.fini:
		case <-time.After(delaiTest):
			t.Error("le parcours de session n'a pas rendu la main à la fin du test")
		}
	})
	return st
}

// ecranSuivant traite les messages du parcours jusqu'à sa prochaine demande
// d'écran, qu'il ouvre. Rend false si le parcours a demandé à quitter.
func (st *sessionDeTest) ecranSuivant() bool {
	st.t.Helper()
	for {
		select {
		case msg := <-st.boite:
			switch m := msg.(type) {
			case demandeEcran:
				envoyerHote(st.t, st.h, m)
				return true
			case tea.QuitMsg:
				st.quitte = true
				return false
			default:
				envoyerHote(st.t, st.h, m)
			}
		case <-time.After(delaiTest):
			st.t.Fatalf("le parcours n'a demandé aucun écran ; écran :\n%s", st.h.View())
			return false
		}
	}
}

// attendreFin attend que le parcours de session se termine.
func (st *sessionDeTest) attendreFin() {
	st.t.Helper()
	select {
	case <-st.fini:
	case <-time.After(delaiTest):
		st.t.Fatalf("le parcours de session ne s'est pas terminé ; écran :\n%s", st.h.View())
	}
}

func (st *sessionDeTest) toucher(k tea.KeyMsg) { st.t.Helper(); envoyerHote(st.t, st.h, k) }

func (st *sessionDeTest) surLeMenu() bool {
	_, ok := st.h.courant.(*menuModel)
	return ok
}

// choisir valide l'opération sous le curseur après n flèches vers le bas,
// puis « saisir un chemin ».
func (st *sessionDeTest) choisir(bas int) {
	st.t.Helper()
	if !st.surLeMenu() {
		st.t.Fatalf("le menu n'est pas affiché :\n%s", st.h.View())
	}
	for range bas {
		st.toucher(touche("down"))
	}
	st.toucher(touche("enter")) // opération
	st.toucher(touche("enter")) // saisir un chemin : l'écran se ferme
}

var toucheQ = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}

// TestQuitterDepuisLeMenu : q, ou « quitter » validé, termine la session en
// code 0 et demande la fin du programme.
func TestQuitterDepuisLeMenu(t *testing.T) {
	cas := []struct {
		nom     string
		touches []tea.KeyMsg
	}{
		{"q", []tea.KeyMsg{toucheQ}},
		{"quitter puis ⏎", []tea.KeyMsg{touche("down"), touche("down"), touche("down"), touche("down"), touche("enter")}},
		{"quitter puis →", []tea.KeyMsg{touche("down"), touche("down"), touche("down"), touche("down"), touche("right")}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			st := lancerSessionDeTest(t)
			if !st.ecranSuivant() || !st.surLeMenu() {
				t.Fatalf("le menu n'est pas le premier écran :\n%s", st.h.View())
			}
			if !strings.Contains(st.h.View(), "quitter") {
				t.Errorf("le menu ne propose pas « quitter » :\n%s", st.h.View())
			}
			for _, k := range c.touches {
				st.toucher(k)
			}
			if st.ecranSuivant() {
				t.Fatalf("la session a affiché un autre écran au lieu de quitter :\n%s", st.h.View())
			}
			st.attendreFin()
			if code := st.s.codeSortie(); code != 0 {
				t.Errorf("code de sortie = %d, attendu 0", code)
			}
		})
	}
}

// TestEchapSurLeMenuNeFaitRien : sur le menu, Échap n'abandonne rien et ne
// quitte pas.
func TestEchapSurLeMenuNeFaitRien(t *testing.T) {
	st := lancerSessionDeTest(t)
	st.ecranSuivant()
	st.toucher(tea.KeyMsg{Type: tea.KeyEsc})
	if !st.surLeMenu() {
		t.Fatalf("Échap a fermé le menu :\n%s", st.h.View())
	}
	select {
	case msg := <-st.boite:
		t.Fatalf("Échap sur le menu a produit %T", msg)
	default:
	}
}

// TestEchapAvantLancementRevientAuMenu : Échap sur l'écran des options
// abandonne le chiffrement et ramène au menu ; rien n'est écrit.
func TestEchapAvantLancementRevientAuMenu(t *testing.T) {
	// Chemin court, tapé dans le dossier courant : chaque frappe coûte un
	// clignotement de curseur (~0,5 s) à la boucle simulée.
	dossier := t.TempDir()
	t.Chdir(dossier)
	source := "s"
	poserFichier(t, source, []byte("à ne pas toucher\n"))
	avant := listerDossier(t, dossier)

	st := lancerSessionDeTest(t)
	st.ecranSuivant()
	st.choisir(0) // chiffrer
	st.ecranSuivant()
	taper(t, st.h, source)
	st.toucher(touche("enter"))
	st.ecranSuivant()
	if !strings.Contains(st.h.View(), "algorithme") {
		t.Fatalf("l'écran des options n'est pas affiché :\n%s", st.h.View())
	}
	if !strings.Contains(st.h.View(), "· chiffrer › options") {
		t.Errorf("le fil d'Ariane ne nomme pas l'opération :\n%s", st.h.View())
	}
	st.toucher(tea.KeyMsg{Type: tea.KeyEsc})
	if !st.ecranSuivant() || !st.surLeMenu() {
		t.Fatalf("Échap n'a pas ramené au menu :\n%s", st.h.View())
	}
	if apres := listerDossier(t, dossier); !slices.Equal(avant, apres) {
		t.Fatalf("Échap a laissé des traces : %v puis %v", avant, apres)
	}
	st.toucher(toucheQ)
	st.ecranSuivant()
	st.attendreFin()
	if code := st.s.codeSortie(); code != 0 {
		t.Errorf("un abandon par Échap compte comme un échec : code %d", code)
	}
}

// TestQSansEffetPendantSaisie : q tapé dans un champ texte s'y écrit, sans
// quitter.
func TestQSansEffetPendantSaisie(t *testing.T) {
	st := lancerSessionDeTest(t)
	st.ecranSuivant()
	st.choisir(0)
	st.ecranSuivant()
	taper(t, st.h, "qq")
	if !strings.Contains(st.h.View(), "qq") {
		t.Fatalf("les q tapés n'apparaissent pas dans le champ :\n%s", st.h.View())
	}
	select {
	case msg := <-st.boite:
		t.Fatalf("q pendant une saisie a produit %T", msg)
	default:
	}
	select {
	case <-st.fini:
		t.Fatal("q pendant une saisie a terminé la session")
	default:
	}
}

// TestCodeSortieApresEchec : une opération ratée montre sa cause dans le
// cadre, ⏎ ramène au menu, puis « quitter » sort en code 1.
func TestCodeSortieApresEchec(t *testing.T) {
	t.Chdir(t.TempDir()) // chemin court : voir TestEchapAvantLancementRevientAuMenu
	abime := "a.chto"
	poserFichier(t, abime, []byte("ceci n'est pas un fichier chiffré"))

	st := lancerSessionDeTest(t)
	st.ecranSuivant()
	st.choisir(1) // déchiffrer
	st.ecranSuivant()
	taper(t, st.h, abime)
	st.toucher(touche("enter"))
	st.ecranSuivant() // lecture de l'en-tête : l'écran se ferme de lui-même
	if !st.ecranSuivant() {
		t.Fatal("aucun écran après l'échec")
	}
	if _, ok := st.h.courant.(*ecranResultat); !ok || !strings.Contains(st.h.View(), "échec") {
		t.Fatalf("la cause de l'échec n'est pas affichée dans le cadre :\n%s", st.h.View())
	}
	st.toucher(touche("enter"))
	if !st.ecranSuivant() || !st.surLeMenu() {
		t.Fatalf("⏎ sur l'écran d'erreur n'a pas ramené au menu :\n%s", st.h.View())
	}
	st.toucher(toucheQ)
	st.ecranSuivant()
	st.attendreFin()
	if code := st.s.codeSortie(); code != 1 {
		t.Errorf("code de sortie = %d, attendu 1", code)
	}
}

// TestCtrlCTermineLaSession : Ctrl+C rend la main au parcours, qui s'arrête
// sans demander de quitter — c'est le programme qui sort, en 130.
func TestCtrlCTermineLaSession(t *testing.T) {
	st := lancerSessionDeTest(t)
	st.ecranSuivant()
	st.toucher(tea.KeyMsg{Type: tea.KeyCtrlC})
	st.attendreFin()
	if st.quitte {
		t.Error("Ctrl+C ne doit pas passer par la sortie normale")
	}
}

// TestEchapApresEcritureGarde : après l'écriture, Échap sur la question de
// suppression ou de renommage vaut « garder » — jamais un échec.
func TestEchapApresEcritureGarde(t *testing.T) {
	t.Run("suppression", func(t *testing.T) {
		h, boite := hoteSynchrone(t, 100, 30)
		type issue struct {
			ok  bool
			err error
		}
		fin := make(chan issue, 1)
		go func() {
			ok, err := demanderSuppression("supprimer ?", "détail")
			fin <- issue{ok, err}
		}()
		demandeRecue(t, h, boite)
		envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
		select {
		case r := <-fin:
			if r.ok || r.err != nil {
				t.Fatalf("demanderSuppression = (%v, %v), attendu (false, nil)", r.ok, r.err)
			}
		case <-time.After(delaiTest):
			t.Fatal("demanderSuppression n'a pas rendu la main")
		}
	})
	t.Run("renommage", func(t *testing.T) {
		dossier := t.TempDir()
		sortie := filepath.Join(dossier, "sortie.txt")
		poserFichier(t, sortie, []byte("clair"))
		h, boite := hoteSynchrone(t, 100, 30)
		issue := make(chan error, 1)
		go func() { issue <- restituerNom(sortie, &pkg.FileMetadata{Name: "origine.txt"}) }()
		demandeRecue(t, h, boite)
		envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
		if err := issueRecue(t, issue); err != nil {
			t.Fatalf("restituerNom après Échap = %v, attendu nil", err)
		}
		if _, err := os.Stat(sortie); err != nil {
			t.Errorf("le fichier a été renommé malgré Échap : %v", err)
		}
	})
}

// TestMenuTouchesAnnonceQuitter : la barre du bas du menu rappelle q.
func TestMenuTouchesAnnonceQuitter(t *testing.T) {
	st := lancerSessionDeTest(t)
	st.ecranSuivant()
	if !strings.Contains(st.h.View(), "q quitter") {
		t.Errorf("la barre du bas du menu ne rappelle pas q :\n%s", st.h.View())
	}
}

// poserFichier et listerDossier : les aides du pty (e2e_pty_test.go) ne
// sont pas compilées sous Windows, ces tests-ci si.
func poserFichier(t *testing.T, chemin string, contenu []byte) {
	t.Helper()
	if err := os.WriteFile(chemin, contenu, 0o600); err != nil {
		t.Fatal(err)
	}
}

func listerDossier(t *testing.T, dossier string) []string {
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

// TestAnnulerLEcrasementNEstPasUnEchec : « annuler » sur la question
// d'écrasement est un choix, pas une panne : retour au menu sans compter
// d'échec, comme Échap.
func TestAnnulerLEcrasementNEstPasUnEchec(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "occupe.chto")
	poserFichier(t, dest, []byte("déjà là"))
	h, boite := hoteSynchrone(t, 100, 30)
	issue := make(chan error, 1)
	go func() {
		_, err := confirmerEcrasement(dest)
		issue <- err
	}()
	demandeRecue(t, h, boite)
	if !strings.Contains(h.View(), "> annuler") {
		t.Fatalf("le curseur n'est pas sur « annuler » :\n%s", h.View())
	}
	envoyerHote(t, h, touche("enter"))
	err := issueRecue(t, issue)
	if err == nil {
		t.Fatal("annuler doit arrêter l'opération")
	}
	if compteCommeEchec(err) {
		t.Errorf("annuler l'écrasement compte comme un échec : %v", err)
	}
	if !strings.Contains(err.Error(), "n'a pas été touché") {
		t.Errorf("le message d'annulation a changé : %v", err)
	}
	for _, e := range []error{errMenu, errQuitter, huh.ErrUserAborted} {
		if compteCommeEchec(e) {
			t.Errorf("%v compte comme un échec", e)
		}
	}
	if !compteCommeEchec(errors.New("mot de passe incorrect")) {
		t.Error("une vraie erreur ne compte pas comme un échec")
	}
}

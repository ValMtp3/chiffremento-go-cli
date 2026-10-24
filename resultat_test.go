package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"chiffremento-cli/pkg"
)

// Carte résultat, écran d'erreur, écran « en cours » et résumés recueillis
// pendant l'écran alternatif.

// TestCarteResultatRevientAuMenu : la carte montre le ✓ et le fichier
// produit, puis ⏎ la referme sans erreur — le parcours repart au menu.
func TestCarteResultatRevientAuMenu(t *testing.T) {
	h := hoteDeTest(t, 84, 30)
	carte := carteResultat([]string{
		fmt.Sprintf("  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render("notes.txt.chto")),
	})
	demande := montrer(t, h, carte)
	vue := h.View()
	for _, attendu := range []string{"✓", "notes.txt.chto", "⏎ revenir au menu"} {
		if !strings.Contains(vue, attendu) {
			t.Errorf("la carte ne montre pas %q :\n%s", attendu, vue)
		}
	}
	envoyerHote(t, h, touche("enter"))
	r, ok := reponseRecue(t, demande)
	if !ok {
		t.Fatal("⏎ n'a pas refermé la carte")
	}
	if r.err != nil {
		t.Errorf("carte refermée par ⏎ : err = %v, attendu nil", r.err)
	}
}

// TestEcranErreurMauvaisePhrase : une mauvaise phrase s'affiche dans le
// cadre, cause seule — aucun conseil n'existe pour elle, on n'en invente
// pas —, puis ⏎ revient au menu.
func TestEcranErreurMauvaisePhrase(t *testing.T) {
	h := hoteDeTest(t, 84, 30)
	demande := montrer(t, h, ecranErreur(pkg.ErrBadPassword))
	vue := h.View()
	if !strings.Contains(vue, pkg.ErrBadPassword.Error()) {
		t.Errorf("la cause n'est pas affichée :\n%s", vue)
	}
	if strings.Contains(vue, "quoi faire") {
		t.Errorf("un conseil est affiché alors qu'aucun n'existe pour cette erreur :\n%s", vue)
	}
	envoyerHote(t, h, touche("enter"))
	if r, ok := reponseRecue(t, demande); !ok || r.err != nil {
		t.Fatalf("⏎ sur l'écran d'erreur : reçu %v, err %v", ok, r.err)
	}
}

// TestEcranErreurQuoiFaire : le conseil vient des messages existants — les
// lignes qui suivent la cause, et l'indice d'indiceForce — sans texte neuf.
func TestEcranErreurQuoiFaire(t *testing.T) {
	cas := []struct {
		nom            string
		err            error
		cause, conseil string
	}{
		{
			"lignes après la cause",
			errors.New("x.chto ne se relit pas (abîmé)\n  x n'a pas été supprimé : c'est la seule copie lisible"),
			"x.chto ne se relit pas (abîmé)",
			"x n'a pas été supprimé : c'est la seule copie lisible",
		},
		{
			"destination existante",
			fmt.Errorf("écriture : %w", pkg.ErrDestinationExistante),
			pkg.ErrDestinationExistante.Error(),
			"déplace-le, renomme-le",
		},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			h := hoteDeTest(t, 84, 30)
			montrer(t, h, ecranErreur(c.err))
			vue := h.View()
			iCause := strings.Index(vue, c.cause)
			iConseil := strings.Index(vue, "quoi faire")
			if iCause < 0 || iConseil < 0 || iConseil < iCause {
				t.Fatalf("attendu la cause puis « quoi faire » :\n%s", vue)
			}
			if !strings.Contains(vue[iConseil:], c.conseil) {
				t.Errorf("le conseil %q manque sous « quoi faire » :\n%s", c.conseil, vue)
			}
		})
	}
}

// TestQuestionSuppressionDansLaCarte : la question de suppression s'affiche
// sous le ✓ de l'opération, curseur sur « garder ».
func TestQuestionSuppressionDansLaCarte(t *testing.T) {
	h, boite := hoteSynchrone(t, 100, 30)
	s := &session{}
	sessionCourante = s
	t.Cleanup(func() { sessionCourante = nil })
	s.noter("résumé d'une opération précédente\n")
	s.ouvrirOperation()
	annoncer(nil, "  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render("brouillon.txt.chto"))

	fin := make(chan error, 1)
	go func() {
		_, err := demanderSuppression("supprimer l'original brouillon.txt ?", "détail")
		fin <- err
	}()
	demandeRecue(t, h, boite)
	vue := h.View()
	iCoche := strings.Index(vue, "✓  brouillon.txt.chto")
	iGarder := strings.Index(vue, "> garder")
	if iCoche < 0 || iGarder < 0 || iGarder < iCoche {
		t.Fatalf("attendu le ✓ puis la question, curseur sur « garder » :\n%s", vue)
	}
	if strings.Contains(vue, "opération précédente") {
		t.Errorf("la carte montre le résumé d'une autre opération :\n%s", vue)
	}
	envoyerHote(t, h, touche("enter"))
	if err := issueRecue(t, fin); err != nil {
		t.Fatalf("demanderSuppression = %v", err)
	}
}

// TestEnCoursPendantLeTravail : pendant un travail sans progression (lecture
// de l'en-tête, changement de mot de passe), le cadre dit ce qui se passe ;
// Échap n'abandonne rien et l'écran se ferme de lui-même à la fin.
func TestEnCoursPendantLeTravail(t *testing.T) {
	h, boite := hoteSynchrone(t, 100, 30)
	bloque := make(chan struct{})
	attendue := errors.New("en-tête illisible")
	issue := make(chan error, 1)
	go func() {
		issue <- enCours("lecture", "lecture de l'en-tête…", func() error {
			<-bloque
			return attendue
		})
	}()
	var demande demandeEcran
	select {
	case msg := <-boite:
		demande = msg.(demandeEcran)
	case <-time.After(delaiTest):
		t.Fatal("aucun écran demandé pendant le travail")
	}
	// Ouvert sans dérouler Init : elle attend la fin du travail.
	_, initCmd := h.Update(demande)
	if vue := h.View(); !strings.Contains(vue, "lecture de l'en-tête…") {
		t.Fatalf("le cadre est vide pendant le travail :\n%s", vue)
	}
	h.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if _, ok := reponseRecue(t, demande); ok {
		t.Fatal("Échap a fermé l'écran d'un travail déjà lancé")
	}
	close(bloque)
	derouleHote(t, h, initCmd, 0)
	if err := issueRecue(t, issue); !errors.Is(err, attendue) {
		t.Fatalf("enCours = %v, attendu %v", err, attendue)
	}
}

// TestEnCoursCtrlCAttendLeTravail : Ctrl+C ferme l'écran, mais enCours ne
// rend la main qu'à la fin du travail — l'appelant effacerait sinon un mot de
// passe encore lu.
func TestEnCoursCtrlCAttendLeTravail(t *testing.T) {
	h, boite := hoteSynchrone(t, 100, 30)
	bloque := make(chan struct{})
	issue := make(chan error, 1)
	go func() {
		issue <- enCours("mots de passe", "changement en cours…", func() error {
			<-bloque
			return nil
		})
	}()
	select {
	case msg := <-boite:
		h.Update(msg)
	case <-time.After(delaiTest):
		t.Fatal("aucun écran demandé pendant le travail")
	}
	h.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	select {
	case err := <-issue:
		t.Fatalf("enCours a rendu la main (%v) avant la fin du travail", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(bloque)
	if err := issueRecue(t, issue); !errors.Is(err, huh.ErrUserAborted) {
		t.Fatalf("enCours = %v, attendu huh.ErrUserAborted", err)
	}
}

// TestCtrlCApresEcritureLeDit : Ctrl+C pendant la fin de l'animation, alors
// que l'opération a déjà écrit sa sortie, sort sans ✓ ni question ; les
// résumés imprimés à la sortie disent que le fichier existe.
func TestCtrlCApresEcritureLeDit(t *testing.T) {
	_, p, fin := lancerHoteDeTest(t)
	ecrit := make(chan struct{})
	issue := make(chan error, 1)
	go func() {
		issue <- runJob(jobInfo{Action: "test", In: "/etc/hosts", Out: "notes.txt.chto", Success: "notes.txt.chto", Ecrit: true},
			func(func(int64, int64)) error {
				defer close(ecrit)
				return nil
			})
	}()
	<-ecrit
	time.Sleep(100 * time.Millisecond) // l'opération a rendu la main, l'animation continue
	p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	select {
	case <-fin:
	case <-time.After(delaiTest):
		t.Fatal("Ctrl+C n'a pas terminé le programme")
	}
	if err := issueRecue(t, issue); !errors.Is(err, huh.ErrUserAborted) {
		t.Fatalf("runJob = %v, attendu huh.ErrUserAborted", err)
	}
	var sortie bytes.Buffer
	sessionCourante.imprimer(&sortie)
	if !strings.Contains(sortie.String(), "notes.txt.chto écrit avant l'interruption") {
		t.Errorf("la sortie écrite avant Ctrl+C n'est pas annoncée : %q", sortie.String())
	}
}

// TestSortieNormaleSansMentionDInterruption : une opération menée à son terme
// annonce son ✓ une seule fois, sans parler d'interruption.
func TestSortieNormaleSansMentionDInterruption(t *testing.T) {
	lancerHoteDeTest(t)
	if err := runJob(jobInfo{Action: "test", In: "/etc/hosts", Out: "a.chto", Success: "a.chto", Ecrit: true},
		func(func(int64, int64)) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var sortie bytes.Buffer
	sessionCourante.imprimer(&sortie)
	if strings.Contains(sortie.String(), "interruption") || strings.Count(sortie.String(), "a.chto") != 1 {
		t.Errorf("résumés inattendus : %q", sortie.String())
	}
}

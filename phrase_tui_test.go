package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
)

// Écran de la phrase de passe générée, proposé à l'étape du mot de passe quand
// on chiffre. Les tests pilotent Update directement : le presse-papier et le
// générateur sont injectés, rien ne touche au vrai presse-papier.

func toucheP(s string) tea.KeyMsg {
	switch s {
	case "entrée":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "échap":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// modeleDeTest renvoie un écran dont la copie et la génération sont observées.
func modeleDeTest(t *testing.T, copie func(string) error) (*modelePhrase, *[]int) {
	t.Helper()
	demandes := []int{}
	n := 0
	generer := func(mots int) (pkg.Phrase, error) {
		demandes = append(demandes, mots)
		n++
		return pkg.Phrase{Texte: strings.Repeat("x", 10) + string(rune('a'+n)), Bits: pkg.EntropiePhrase(mots)}, nil
	}
	m, err := newModelePhrase(pkg.DefautMotsPhrase, copie, generer)
	if err != nil {
		t.Fatal(err)
	}
	return m, &demandes
}

func appliquer(m *modelePhrase, msgs ...tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	for _, msg := range msgs {
		_, cmd = m.Update(msg)
	}
	return cmd
}

func TestPhraseMasqueeParDefaut(t *testing.T) {
	m, _ := modeleDeTest(t, nil)
	if strings.Contains(m.View(), m.phrase.Texte) {
		t.Fatal("la phrase est visible à l'ouverture de l'écran")
	}
	appliquer(m, toucheP("a"))
	if !strings.Contains(m.View(), m.phrase.Texte) {
		t.Error("« a » n'affiche pas la phrase")
	}
	appliquer(m, toucheP("a"))
	if strings.Contains(m.View(), m.phrase.Texte) {
		t.Error("un second « a » ne masque pas la phrase")
	}
}

func TestPhraseAfficheEntropie(t *testing.T) {
	m, _ := modeleDeTest(t, nil)
	if !strings.Contains(m.View(), "128 bits") {
		t.Errorf("l'entropie n'est pas annoncée :\n%s", m.View())
	}
}

func TestPhraseCopie(t *testing.T) {
	var copiee string
	m, _ := modeleDeTest(t, func(s string) error { copiee = s; return nil })
	appliquer(m, toucheP("c"))
	if copiee != m.phrase.Texte {
		t.Fatalf("copié %q, attendu %q", copiee, m.phrase.Texte)
	}
	vue := m.View()
	if !strings.Contains(vue, "copiée") {
		t.Errorf("aucune confirmation de copie :\n%s", vue)
	}
	// Le presse-papier n'est jamais vidé : l'utilisateur doit le savoir.
	if !strings.Contains(vue, "presse-papier") {
		t.Errorf("rien ne dit que la phrase reste dans le presse-papier :\n%s", vue)
	}
	if strings.Contains(vue, m.phrase.Texte) {
		t.Error("copier ne doit pas afficher la phrase")
	}
}

func TestPhraseCopieEnEchec(t *testing.T) {
	m, _ := modeleDeTest(t, func(string) error { return errors.New("xclip introuvable") })
	appliquer(m, toucheP("c"))
	if !strings.Contains(m.View(), "xclip introuvable") {
		t.Errorf("l'échec de la copie n'est pas expliqué :\n%s", m.View())
	}
}

func TestPhraseRegenererEtNombreDeMots(t *testing.T) {
	m, demandes := modeleDeTest(t, nil)
	avant := m.phrase.Texte
	appliquer(m, toucheP("r"))
	if m.phrase.Texte == avant {
		t.Error("« r » n'a pas produit de nouvelle phrase")
	}
	appliquer(m, toucheP("+"))
	if m.mots != pkg.DefautMotsPhrase+1 {
		t.Errorf("« + » : %d mots, attendu %d", m.mots, pkg.DefautMotsPhrase+1)
	}
	for range 10 {
		appliquer(m, toucheP("-"))
	}
	if m.mots != pkg.MinMotsPhrase {
		t.Errorf("« - » descend à %d mots, minimum %d", m.mots, pkg.MinMotsPhrase)
	}
	for _, n := range *demandes {
		if n < pkg.MinMotsPhrase {
			t.Errorf("génération demandée avec %d mots", n)
		}
	}
	// Changer le nombre de mots remet la phrase sous masque : la nouvelle
	// n'a pas été demandée à l'affichage.
	appliquer(m, toucheP("a"), toucheP("+"))
	if m.visible {
		t.Error("une nouvelle phrase s'affiche sans qu'on l'ait demandé")
	}
}

func TestPhraseSortiesDeLEcran(t *testing.T) {
	m, _ := modeleDeTest(t, nil)
	if cmd := appliquer(m, toucheP("entrée")); cmd == nil || m.issue != issueContinuer {
		t.Errorf("entrée : issue %v", m.issue)
	}
	m, _ = modeleDeTest(t, nil)
	if appliquer(m, toucheP("échap")); m.issue != issueRetour {
		t.Errorf("échap : issue %v, attendu retour", m.issue)
	}
	m, _ = modeleDeTest(t, nil)
	cmd := appliquer(m, toucheP("ctrl+c"))
	if cmd == nil {
		t.Fatal("ctrl+c ignoré")
	}
	if _, ok := cmd().(tea.InterruptMsg); !ok {
		t.Errorf("ctrl+c renvoie %T, attendu tea.InterruptMsg", cmd())
	}
}

// TestPhraseGenereePasseLeControleDeForce : une phrase proposée par l'outil
// ne doit jamais être refusée par son propre contrôle de robustesse.
func TestPhraseGenereePasseLeControleDeForce(t *testing.T) {
	for range 50 {
		p, err := pkg.GenererPhrase(pkg.MinMotsPhrase)
		if err != nil {
			t.Fatal(err)
		}
		if err := validatePassword(p.Texte); err != nil {
			t.Fatalf("phrase générée refusée : %q : %v", p.Texte, err)
		}
	}
}

func TestDoGenpass(t *testing.T) {
	sortie := captureSortie(t)
	if err := doGenpass(pkg.DefautMotsPhrase); err != nil {
		t.Fatal(err)
	}
	os.Stdout.Sync()
	b, err := os.ReadFile(sortie)
	if err != nil {
		t.Fatal(err)
	}
	lignes := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	// Sur stdout, la phrase seule : `chiffremento -mode genpass | pbcopy`.
	if len(lignes) != 1 || len(lignes[0]) < 40 {
		t.Errorf("sortie standard %q : attendu la phrase seule sur une ligne", b)
	}
	if err := doGenpass(pkg.MinMotsPhrase - 1); err == nil {
		t.Error("-mots sous le minimum accepté")
	}
}

// TestSecretChoisi : la phrase générée chiffre le fichier quand elle est
// choisie, et un mot de passe saisi plus tôt — puis abandonné au profit de la
// phrase — ne doit jamais servir à sa place.
func TestSecretChoisi(t *testing.T) {
	o := &optionsChiffrement{password: "saisi-puis-abandonne", phrase: "Phrase#Generee7"}
	o.genererPhrase = true
	if got := secretChoisi(o); got != "Phrase#Generee7" {
		t.Errorf("phrase choisie, secret %q", got)
	}
	o.genererPhrase = false
	if got := secretChoisi(o); got != "saisi-puis-abandonne" {
		t.Errorf("saisie choisie, secret %q", got)
	}
}

// TestPhraseRemasqueeEnQuittant : Bubble Tea laisse sa dernière image dans le
// terminal. Une phrase affichée avec « a » resterait en clair dans le
// défilement, une capture ou un journal tmux après la sortie de l'écran.
func TestPhraseRemasqueeEnQuittant(t *testing.T) {
	for _, sortie := range []string{"entrée", "échap", "ctrl+c"} {
		m, _ := modeleDeTest(t, nil)
		appliquer(m, toucheP("a"), toucheP(sortie))
		if strings.Contains(m.View(), m.phrase.Texte) {
			t.Errorf("%s : la phrase reste en clair dans la dernière image", sortie)
		}
	}
}

// TestPhraseMasqueSansLongueur : un masque d'autant de points que de
// caractères donnerait la longueur de la phrase à qui regarde l'écran, et
// donc un indice sur les mots tirés.
func TestPhraseMasqueSansLongueur(t *testing.T) {
	m, _ := modeleDeTest(t, nil)
	courte := m.View()
	m.phrase.Texte = strings.Repeat("y", 70)
	if longue := m.View(); longue != courte {
		t.Error("le masque change avec la longueur de la phrase")
	}
}

// TestEtapePhraseParLHote : avec un hôte, la phrase s'affiche dans le cadre,
// sans programme à part, puis la question de confirmation ; la phrase n'est
// rendue qu'après « oui ». Échap, lui, ramène au menu.
func TestEtapePhraseParLHote(t *testing.T) {
	h, boite := hoteSynchrone(t, 100, 30)
	type resultat struct {
		phrase string
		err    error
	}
	issue := make(chan resultat, 1)
	go func() {
		p, err := etapePhrase()
		issue <- resultat{p.Texte, err}
	}()

	demandeRecue(t, h, boite)
	if !strings.Contains(h.View(), "phrase de passe générée") {
		t.Fatalf("la phrase n'est pas dans le cadre :\n%s", h.View())
	}
	envoyerHote(t, h, toucheP("entrée"))
	demandeRecue(t, h, boite)
	if !strings.Contains(h.View(), "as-tu enregistré cette phrase") {
		t.Fatalf("la confirmation n'est pas dans le cadre :\n%s", h.View())
	}
	envoyerHote(t, h, touche("up"))
	envoyerHote(t, h, toucheP("entrée"))

	var r resultat
	select {
	case r = <-issue:
	case <-time.After(delaiTest):
		t.Fatal("etapePhrase n'a pas rendu la main")
	}
	if r.err != nil || r.phrase == "" {
		t.Fatalf("etapePhrase = (%q, %v), attendu une phrase", r.phrase, r.err)
	}

	go func() {
		p, err := etapePhrase()
		issue <- resultat{p.Texte, err}
	}()
	demandeRecue(t, h, boite)
	envoyerHote(t, h, toucheP("échap"))
	select {
	case r = <-issue:
	case <-time.After(delaiTest):
		t.Fatal("etapePhrase n'a pas rendu la main après Échap")
	}
	if !errors.Is(r.err, errMenu) || r.phrase != "" {
		t.Fatalf("Échap : etapePhrase = (%q, %v), attendu errMenu", r.phrase, r.err)
	}
}

package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/ansi"
)

// Un champ texte affiche un seul « > » devant sa valeur, comme le curseur
// des listes. Lipgloss ajoute le texte de SetString à celui qu'on lui passe :
// un prompt déjà posé par huh, puis répété par le thème, donnait « >  > ».
func TestThemeUnSeulChevronParChampTexte(t *testing.T) {
	champ := huh.NewInput().Title("chemin")
	form := huh.NewForm(huh.NewGroup(champ)).WithTheme(formTheme()).WithWidth(60)
	form.Init()

	vue := ansi.Strip(form.View())
	ligne := ""
	for _, l := range strings.Split(vue, "\n") {
		if strings.Contains(l, ">") {
			ligne = l
			break
		}
	}
	if ligne == "" {
		t.Fatalf("aucun chevron dans le champ texte :\n%s", vue)
	}
	if n := strings.Count(ligne, ">"); n != 1 {
		t.Errorf("%d chevrons devant le champ, un seul attendu : %q", n, ligne)
	}
}

// Même règle pour un champ qui n'a pas le focus : le second champ du groupe
// est inactif, son prompt vient du thème « Blurred ».
func TestThemeUnSeulChevronChampSansFocus(t *testing.T) {
	premier := huh.NewInput().Title("premier")
	second := huh.NewInput().Title("second")
	form := huh.NewForm(huh.NewGroup(premier, second)).WithTheme(formTheme()).WithWidth(60)
	form.Init()

	vue := ansi.Strip(form.View())
	lignes := 0
	for _, l := range strings.Split(vue, "\n") {
		if !strings.Contains(l, ">") {
			continue
		}
		lignes++
		if n := strings.Count(l, ">"); n != 1 {
			t.Errorf("%d chevrons devant le champ, un seul attendu : %q", n, l)
		}
	}
	if lignes != 2 {
		t.Errorf("%d champs avec chevron, 2 attendus :\n%s", lignes, vue)
	}
}

func TestVersionAffichee(t *testing.T) {
	cas := map[string]string{
		"2.4.0":      "v2.4.0", // goreleaser, sans « v »
		"v2.4.0":     "v2.4.0", // Makefile (git describe)
		"v2.4.0-3-g": "v2.4.0-3-g",
		"dev":        "dev",
		"":           "",
	}
	for entree, attendu := range cas {
		if got := versionAffichee(entree); got != attendu {
			t.Errorf("versionAffichee(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
}

func TestFilDArianeVersionAvecV(t *testing.T) {
	avant := version
	t.Cleanup(func() { version = avant })
	version = "2.4.0"
	if got := filDAriane("chiffrer", "options"); got != "chiffremento v2.4.0 · chiffrer › options" {
		t.Errorf("fil = %q", got)
	}
}

package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// TestLargeurCadre : le cadre prend la largeur du terminal moins une marge,
// bornée à 52..80 ; en petit terminal, il prend toute la place.
func TestLargeurCadre(t *testing.T) {
	cas := []struct{ terminal, attendu int }{
		{40, 40},
		{56, 52},
		{60, 56},
		{100, 80},
		{200, 80},
	}
	for _, c := range cas {
		if obtenu := largeurCadre(c.terminal); obtenu != c.attendu {
			t.Errorf("largeurCadre(%d) = %d, attendu %d", c.terminal, obtenu, c.attendu)
		}
	}
}

// TestPetitTerminalMasqueLesBarres : sous 56 colonnes ou 16 lignes, les barres
// disparaissent pour laisser toute la place au cadre.
func TestPetitTerminalMasqueLesBarres(t *testing.T) {
	if !petitTerminal(50, 12) {
		t.Fatal("50×12 n'est pas reconnu comme un petit terminal")
	}
	if petitTerminal(100, 30) {
		t.Fatal("100×30 est pris pour un petit terminal")
	}
	vue := disposer(50, 12, "BARRE-HAUT", "corps", "BARRE-BAS")
	if strings.Contains(vue, "BARRE-HAUT") || strings.Contains(vue, "BARRE-BAS") {
		t.Errorf("barres affichées en 50×12 :\n%s", vue)
	}
	if !strings.Contains(vue, "corps") {
		t.Errorf("le corps a disparu en 50×12 :\n%s", vue)
	}

	h := hoteDeTest(t, 50, 12)
	if strings.Contains(h.View(), "chiffremento") {
		t.Errorf("la barre du haut de l'hôte est affichée en 50×12 :\n%s", h.View())
	}
}

// TestDispositionCentree : chaque ligne du cadre commence à la même colonne,
// celle qui centre un cadre de 80 dans 100 colonnes.
func TestDispositionCentree(t *testing.T) {
	const largeur, hauteur = 100, 40
	vue := disposer(largeur, hauteur, "haut", "une ligne\nune autre ligne plus longue", "bas")
	lignes := strings.Split(vue, "\n")
	if len(lignes) != hauteur {
		t.Fatalf("%d lignes, attendu %d", len(lignes), hauteur)
	}
	margeAttendue := (largeur - 80) / 2
	lignesDuCadre := 0
	for _, ligne := range lignes {
		texte := strings.TrimLeft(ligne, " ")
		if !strings.HasPrefix(texte, "┌") && !strings.HasPrefix(texte, "│") && !strings.HasPrefix(texte, "└") {
			continue
		}
		lignesDuCadre++
		if marge := len(ligne) - len(texte); marge != margeAttendue {
			t.Errorf("marge gauche %d, attendu %d : %q", marge, margeAttendue, ligne)
		}
		if w := lipgloss.Width(ligne); w != margeAttendue+80 {
			t.Errorf("ligne du cadre de largeur %d, attendu %d : %q", w, margeAttendue+80, ligne)
		}
	}
	if lignesDuCadre < 4 {
		t.Fatalf("%d lignes de cadre trouvées, attendu au moins 4 :\n%s", lignesDuCadre, vue)
	}
	if !strings.HasPrefix(strings.TrimLeft(lignes[0], " "), "haut") {
		t.Errorf("la barre du haut n'est pas sur la première ligne : %q", lignes[0])
	}
	if !strings.HasPrefix(strings.TrimLeft(lignes[hauteur-1], " "), "bas") {
		t.Errorf("la barre du bas n'est pas sur la dernière ligne : %q", lignes[hauteur-1])
	}
}

// TestDispositionTronqueLesLignesTropLongues : une ligne de corps plus large
// que le cadre est coupée, jamais repliée sous la bordure.
func TestDispositionTronqueLesLignesTropLongues(t *testing.T) {
	vue := disposer(60, 20, strings.Repeat("h", 200), strings.Repeat("é", 200), strings.Repeat("b", 200))
	for _, ligne := range strings.Split(vue, "\n") {
		if w := lipgloss.Width(ligne); w > 60 {
			t.Errorf("ligne de largeur %d > 60 : %q", w, ligne)
		}
	}
	if !strings.Contains(vue, "…") {
		t.Errorf("la troncature n'est pas signalée par « … » :\n%s", vue)
	}
}

// TestDispositionBornesDegenerees : un terminal sans taille ou d'une seule
// ligne ne fait pas paniquer la mise en page.
func TestDispositionBornesDegenerees(t *testing.T) {
	for _, taille := range [][2]int{{0, 0}, {1, 1}, {3, 2}, {10, 3}, {-5, -5}} {
		vue := disposer(taille[0], taille[1], "haut", "corps\navec\nplusieurs\nlignes", "bas")
		for _, ligne := range strings.Split(vue, "\n") {
			if w := lipgloss.Width(ligne); w > max(taille[0], 0) {
				t.Errorf("%v : ligne de largeur %d : %q", taille, w, ligne)
			}
		}
	}
}

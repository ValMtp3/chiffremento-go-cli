package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Mise en page plein écran : une barre en haut, une barre en bas, et entre
// les deux un cadre centré qui contient l'écran courant.
//
// Toutes les largeurs sont mesurées en colonnes (lipgloss.Width, ansi), jamais
// en octets : « é », « › » ou « ● » prennent plusieurs octets mais une seule
// colonne, et len décalerait la bordure de droite.
const (
	// Le cadre ne descend pas sous la largeur historique de l'interface
	// (contentWidth) et ne dépasse pas 80 colonnes : au-delà, une ligne de
	// texte devient pénible à suivre des yeux.
	largeurCadreMin = contentWidth
	largeurCadreMax = 80
	// margeCadre : deux colonnes de chaque côté, pour que le cadre ne colle
	// pas au bord de la fenêtre.
	margeCadre = 4

	// Sous ces dimensions, les barres prendraient la place du formulaire :
	// on les masque et le cadre occupe tout le terminal.
	largeurMinBarres = largeurCadreMin + margeCadre
	hauteurMinBarres = 16

	// bordureEtMarge : une colonne de bordure et une d'espace de chaque côté
	// du texte, comme le Padding(0, 1) d'un cadre lipgloss.
	bordureEtMarge = 4
)

// largeurCadre donne la largeur totale du cadre, bordures comprises.
func largeurCadre(largeurTerminal int) int {
	if largeurTerminal < largeurMinBarres {
		return max(largeurTerminal, 0)
	}
	return min(max(largeurTerminal-margeCadre, largeurCadreMin), largeurCadreMax)
}

// petitTerminal dit si les barres doivent disparaître.
func petitTerminal(largeur, hauteur int) bool {
	return largeur < largeurMinBarres || hauteur < hauteurMinBarres
}

// hauteurZoneCadre est le nombre de lignes laissées au cadre, bordures
// comprises : tout le terminal, moins les deux barres quand elles sont là.
func hauteurZoneCadre(largeur, hauteur int) int {
	if petitTerminal(largeur, hauteur) {
		return max(hauteur, 0)
	}
	return hauteur - 2
}

// tailleInterieure est la place laissée au texte de l'écran courant. C'est
// elle, et non la taille du terminal, que l'hôte transmet aux sous-écrans.
func tailleInterieure(largeur, hauteur int) (int, int) {
	return max(largeurCadre(largeur)-bordureEtMarge, 0), max(hauteurZoneCadre(largeur, hauteur)-2, 0)
}

// tronquer coupe un texte à la largeur donnée, en le signalant par « … ».
// Il respecte les séquences de couleur : un texte stylé reste stylé.
func tronquer(texte string, largeur int) string {
	if largeur <= 0 {
		return ""
	}
	return ansi.Truncate(texte, largeur, "…")
}

// disposer assemble l'écran complet : exactement `hauteur` lignes, aucune
// plus large que `largeur`. Les barres et le cadre partagent la même marge
// gauche, pour que l'ensemble se lise comme un seul bloc centré.
func disposer(largeur, hauteur int, haut, corps, bas string) string {
	if largeur <= 0 || hauteur <= 0 {
		return ""
	}
	l := largeurCadre(largeur)
	marge := strings.Repeat(" ", (largeur-l)/2)
	avecBarres := !petitTerminal(largeur, hauteur)
	zone := hauteurZoneCadre(largeur, hauteur)

	cadre := encadrer(corps, l, zone)
	dessus := (zone - len(cadre)) / 2

	lignes := make([]string, 0, hauteur)
	if avecBarres {
		lignes = append(lignes, marge+tronquer(haut, l))
	}
	for range dessus {
		lignes = append(lignes, "")
	}
	for _, ligne := range cadre {
		lignes = append(lignes, marge+ligne)
	}
	for len(lignes) < hauteur-1 {
		lignes = append(lignes, "")
	}
	if avecBarres {
		lignes = append(lignes, marge+tronquer(bas, l))
	} else if len(lignes) < hauteur {
		lignes = append(lignes, "")
	}
	return strings.Join(lignes, "\n")
}

// encadrer dessine le cadre autour du corps, sur `largeur` colonnes et au
// plus `hauteurMax` lignes. Une ligne trop longue est coupée plutôt que
// repliée : repliée, elle repousserait la bordure du bas hors de l'écran.
func encadrer(corps string, largeur, hauteurMax int) []string {
	lignes := strings.Split(strings.TrimRight(corps, "\n"), "\n")

	// Trop petit pour une bordure : le texte seul, coupé à la place qui reste.
	if largeur < bordureEtMarge+1 || hauteurMax < 3 {
		lignes = lignes[:min(len(lignes), max(hauteurMax, 0))]
		coupees := make([]string, len(lignes))
		for i, ligne := range lignes {
			coupees[i] = tronquer(ligne, largeur)
		}
		return coupees
	}

	interieur := largeur - bordureEtMarge
	if place := hauteurMax - 2; len(lignes) > place {
		// La dernière ligne visible annonce qu'il en manque.
		lignes = append(lignes[:place-1:place-1], "…")
	}

	trait := styleFaint.Render(strings.Repeat("─", largeur-2))
	bord := styleFaint.Render("│")
	cadre := make([]string, 0, len(lignes)+2)
	cadre = append(cadre, styleFaint.Render("┌")+trait+styleFaint.Render("┐"))
	for _, ligne := range lignes {
		ligne = tronquer(ligne, interieur)
		cadre = append(cadre, bord+" "+ligne+strings.Repeat(" ", interieur-lipgloss.Width(ligne))+" "+bord)
	}
	cadre = append(cadre, styleFaint.Render("└")+trait+styleFaint.Render("┘"))
	return cadre
}

// barre compose une barre d'une ligne : `gauche` au début, `droite` collé au
// bord droit. Quand la place manque, c'est la partie gauche qui est coupée :
// à droite se trouvent ce qui ne doit jamais disparaître (l'indicateur de
// phrase en mémoire, ctrl+c).
func barre(gauche, droite string, largeur int, styleGauche, styleDroite lipgloss.Style) string {
	if largeur <= 0 {
		return ""
	}
	if droite == "" {
		return styleGauche.Render(tronquer(gauche, largeur))
	}
	place := largeur - lipgloss.Width(droite) - 1
	if place < 1 {
		return styleDroite.Render(tronquer(droite, largeur))
	}
	gauche = tronquer(gauche, place)
	espace := strings.Repeat(" ", largeur-lipgloss.Width(gauche)-lipgloss.Width(droite))
	return styleGauche.Render(gauche) + espace + styleDroite.Render(droite)
}

package main

import "strings"

// Écran d'aide, ouvert par ? depuis n'importe quel écran qui n'attend pas de
// texte. Il dit en deux phrases ce que fait l'outil, puis les touches.
//
// Le tableau doit rester identique à celui du README (FR et EN) : c'est la
// même promesse, faite à deux endroits.

// touchesAide est la barre du bas pendant que l'aide est ouverte.
const touchesAide = "? échap ⏎ fermer"

// raccourci : une touche et ce qu'elle fait.
type raccourci struct{ touche, role string }

var raccourcis = []raccourci{
	{"↑ ↓", "parcourir les réponses"},
	{"→ ou ⏎", "valider"},
	{"←", "revenir à la décision précédente"},
	{"shift+tab", "revenir, dans un champ texte ou l'explorateur"},
	{"échap", "abandonner l'opération, retour au menu"},
	{"", "dans l'explorateur : remonter d'un dossier"},
	{"q", "quitter, depuis le menu"},
	{"?", "ouvrir ou fermer cette aide"},
	{"ctrl+c", "quitter tout de suite"},
}

// largeurColonneTouche aligne les rôles : ils commencent tous à la même
// colonne, comme les valeurs de l'écran de progression.
const largeurColonneTouche = 11

const presentationOutil = "chiffremento chiffre et déchiffre fichiers et dossiers " +
	"avec une phrase de passe, sur cette machine uniquement. " +
	"Avant son lancement, une opération s'abandonne sans rien écrire."

// vueAide rend l'aide pour la largeur intérieure du cadre.
func vueAide(largeur int) string {
	var b strings.Builder
	b.WriteString(styleAccent.Render("aide"))
	b.WriteString("\n\n")
	// Le paragraphe est replié au mot près ; le tableau, lui, est coupé par le
	// cadre si la place manque, pour ne jamais casser l'alignement.
	b.WriteString(styleText.Width(max(largeur, 1)).Render(presentationOutil))
	b.WriteString("\n\n")
	b.WriteString(styleDim.Render("raccourcis"))
	b.WriteString("\n")
	colonne := styleAccent.Width(largeurColonneTouche)
	for _, r := range raccourcis {
		b.WriteString("\n")
		b.WriteString(colonne.Render(r.touche))
		b.WriteString(styleText.Render(r.role))
	}
	return b.String()
}

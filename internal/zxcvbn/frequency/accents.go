package frequency

import (
	"strings"
	"unicode/utf8"
)

// MarqueVariante ouvre, dans un fichier de liste, une ligne qui est la forme
// sans accent de la ligne précédente : même rang. Le générateur
// (outils/genlistes) l'écrit, listeDepuisTexte la lit.
const MarqueVariante = "\t"

// lettreSansAccent rend la ou les lettres sans accent d'une lettre accentuée
// du français (minuscules), et false pour toute autre lettre.
func lettreSansAccent(r rune) (string, bool) {
	switch r {
	case 'é', 'è', 'ê', 'ë':
		return "e", true
	case 'à', 'â', 'ä':
		return "a", true
	case 'î', 'ï':
		return "i", true
	case 'ô', 'ö':
		return "o", true
	case 'ù', 'û', 'ü':
		return "u", true
	case 'ÿ':
		return "y", true
	case 'ç':
		return "c", true
	case 'œ':
		return "oe", true
	case 'æ':
		return "ae", true
	}
	return "", false
}

// Accents détachés (« diacritiques combinants ») : une saisie décomposée (NFD),
// collée depuis le Finder par exemple, écrit « é » comme « e » suivi de U+0301.
const (
	premierAccentDetache = '\u0300'
	dernierAccentDetache = '\u036f'
)

// recomposees rassemble une lettre et son accent détaché en la lettre
// accentuée du français (minuscules) : « e » + U+0301 donne « é ».
var recomposees = strings.NewReplacer(
	"e\u0301", "é", "e\u0300", "è", "e\u0302", "ê", "e\u0308", "ë",
	"a\u0300", "à", "a\u0302", "â", "a\u0308", "ä",
	"i\u0302", "î", "i\u0308", "ï",
	"o\u0302", "ô", "o\u0308", "ö",
	"u\u0300", "ù", "u\u0302", "û", "u\u0308", "ü",
	"y\u0308", "ÿ", "c\u0327", "ç",
)

func estAccentDetache(r rune) bool {
	return r >= premierAccentDetache && r <= dernierAccentDetache
}

// SansAccent rend un mot déjà en minuscules sans ses accents : lettres
// accentuées du français retirées (œ et æ donnent deux lettres) et accents
// détachés supprimés. Un mot inchangé est rendu tel quel, sans allocation :
// c'est le cas courant à chaque frappe.
func SansAccent(mot string) string {
	if estASCII(mot) {
		return mot
	}
	var resultat strings.Builder
	for i, r := range mot {
		remplacement, change := lettreSansAccent(r)
		if !change && !estAccentDetache(r) {
			if resultat.Cap() > 0 {
				resultat.WriteRune(r)
			}
			continue
		}
		if resultat.Cap() == 0 {
			resultat.Grow(len(mot))
			resultat.WriteString(mot[:i])
		}
		resultat.WriteString(remplacement)
	}
	if resultat.Cap() == 0 {
		return mot
	}
	return resultat.String()
}

// Recomposer rend un mot déjà en minuscules saisi décomposé (NFD) sous sa
// forme composée, pour les lettres accentuées du français : « he\u0301lène »
// devient « hélène ». Un mot sans accent détaché est rendu tel quel, sans
// allocation.
func Recomposer(mot string) string {
	if estASCII(mot) || !strings.ContainsFunc(mot, estAccentDetache) {
		return mot
	}
	return recomposees.Replace(mot)
}

func estASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

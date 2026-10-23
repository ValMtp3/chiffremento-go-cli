package zxcvbn

import (
	"math"
	"strings"
	"testing"

	"chiffremento-cli/internal/zxcvbn/frequency"
)

// seuilFaible : même valeur que bitsFaible dans tui.go (le paquet main n'est
// pas importable d'ici). Sous ce seuil, l'interface annonce « faible ».
const seuilFaible = 35

func bitsDe(p string) float64 {
	return math.Log2(PasswordStrength(p, nil).Guesses)
}

// Un mot français courant, un prénom ou un nom de famille doivent être annoncés
// faibles : majuscules, accents et année collée comprises.
func TestMotFrancaisFaible(t *testing.T) {
	fixerAnneeReference(t, anneeReferenceParite)
	for _, p := range []string{
		"soleil", "abandon", "marie", "dupont", "Martin", "DUPONT",
		"hélène1990", "helene1990", "Françoise",
	} {
		t.Run(p, func(t *testing.T) {
			if bits := bitsDe(p); bits >= seuilFaible {
				t.Errorf("%q : %.1f bits, moins de %d attendus", p, bits, seuilFaible)
			}
		})
	}
}

// Les mots de la liste de phrases de passe ont tous le même rang : 7 776, soit
// environ 12,9 bits, ce que vaut un tirage au hasard dans cette liste.
func TestMotsFrancaisRangFixe(t *testing.T) {
	for _, p := range []string{"abaisse", "noisette"} {
		t.Run(p, func(t *testing.T) {
			sequence := PasswordStrength(p, nil).Sequence
			if len(sequence) != 1 {
				t.Fatalf("%d éléments dans la séquence, 1 attendu", len(sequence))
			}
			m := sequence[0]
			if m.Pattern != "dictionary" || m.DictionaryName != "mots_fr" || m.Rank != 7776 {
				t.Errorf("motif %q, dictionnaire %q, rang %d ; attendu dictionary, mots_fr, 7776",
					m.Pattern, m.DictionaryName, m.Rank)
			}
		})
	}
}

func TestListesFrancaises(t *testing.T) {
	listes := frequency.Francais()
	for _, nom := range []string{"mots_fr", "prenoms_fr", "noms_fr"} {
		if _, ok := listes[nom]; !ok {
			t.Fatalf("liste %q absente", nom)
		}
	}
	if listes["mots_fr"].RangFixe != 7776 {
		t.Errorf("mots_fr : rang fixe %d, 7776 attendu", listes["mots_fr"].RangFixe)
	}
	for _, nom := range []string{"prenoms_fr", "noms_fr"} {
		liste := listes[nom]
		if len(liste.Mots) < 10000 {
			t.Errorf("%s : %d entrées, au moins 10000 attendues", nom, len(liste.Mots))
		}
		if liste.RangFixe != 0 {
			t.Errorf("%s : rang fixe %d, rang par position attendu", nom, liste.RangFixe)
		}
		for i, mot := range liste.Mots {
			if mot == "" || strings.Contains(mot, "_prenoms_rares") {
				t.Fatalf("%s, entrée n°%d : %q", nom, i+1, mot)
			}
		}
	}
	if premier := listes["noms_fr"].Mots[0]; premier != "martin" {
		t.Errorf("noms_fr : premier nom %q, martin attendu", premier)
	}
}

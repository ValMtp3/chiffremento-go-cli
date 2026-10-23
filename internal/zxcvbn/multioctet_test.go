package zxcvbn

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"chiffremento-cli/internal/zxcvbn/matching"
)

// Positions en octets : I est le premier octet d'un motif, J son dernier.
// zxcvbn v1.0.1 mélangeait par endroits « dernier octet » et « début du dernier
// caractère » : avec des caractères sur plusieurs octets, le produit des
// essais pouvait tomber à 0 (0 bit, « faible ») et la séquence se découper de
// travers.

// verifierSequence contrôle qu'une évaluation est utilisable : au moins un
// essai, et une séquence qui pave exactement le mot de passe (motifs contigus,
// sans trou ni chevauchement, chaque jeton égal au morceau qu'il couvre).
func verifierSequence(t *testing.T, motDePasse string) {
	t.Helper()
	resultat := PasswordStrength(motDePasse, nil)
	if !(resultat.Guesses > 0) {
		t.Errorf("%q : %v essais, plus de 0 attendu", motDePasse, resultat.Guesses)
	}
	var pave strings.Builder
	finPrecedente := -1
	for _, m := range resultat.Sequence {
		if m.I != finPrecedente+1 || m.J < m.I || m.J >= len(motDePasse) {
			t.Errorf("%q : motif %s %q en %d-%d après une fin en %d", motDePasse, m.Pattern, m.Token, m.I, m.J, finPrecedente)
			return
		}
		if morceau := motDePasse[m.I : m.J+1]; m.Token != morceau {
			t.Errorf("%q : motif %s, jeton %q mais morceau couvert %q", motDePasse, m.Pattern, m.Token, morceau)
		}
		pave.WriteString(motDePasse[m.I : m.J+1])
		finPrecedente = m.J
	}
	if pave.String() != motDePasse || finPrecedente != len(motDePasse)-1 {
		t.Errorf("%q : la séquence couvre %q (fin en %d)", motDePasse, pave.String(), finPrecedente)
	}
}

func TestMotDePasseAccentueJamaisZeroEssai(t *testing.T) {
	for _, motDePasse := range []string{"chloééé!", "€azertyéééx", "ééé", "xééé!", "pässwörd!"} {
		t.Run(motDePasse, func(t *testing.T) { verifierSequence(t, motDePasse) })
	}
}

// Après un mot finissant par une lettre sur deux octets, un caractère de plus
// ne doit pas faire perdre le mot : « andré » + « x », pas « and » + « réx ».
func TestPrenomSuiviDUnCaractere(t *testing.T) {
	for _, motDePasse := range []string{"andréx", "andré.", "andré€"} {
		t.Run(motDePasse, func(t *testing.T) {
			premier := PasswordStrength(motDePasse, nil).Sequence[0]
			if premier.Pattern != "dictionary" || premier.Token != "andré" {
				t.Errorf("premier motif %s %q, attendu dictionary « andré »", premier.Pattern, premier.Token)
			}
			verifierSequence(t, motDePasse)
		})
	}
}

// Propriété sur un corpus pseudo-aléatoire fixe (graine 1) : ASCII, lettres
// accentuées composées et décomposées (NFD), symbole sur 3 octets (€),
// idéogramme (日), répétitions et années.
func TestSequencePaveToujoursLeMotDePasse(t *testing.T) {
	fixerAnneeReference(t, anneeReferenceParite)
	morceaux := []string{
		"a", "x", "Z", "!", ".", "1990", "12", "azerty", "pass", "qwe",
		"é", "ééé", "ö", "ç", "œ", "andré", "zoé", "chloé", "lefèvre", "hélène", "érdna",
		"é", "Hélène", "€", "日", "日本", "aéaé", "€€",
	}
	const nbMotsDePasse = 3000
	aleatoire := rand.New(rand.NewSource(1))
	for n := 0; n < nbMotsDePasse; n++ {
		var motDePasse strings.Builder
		for k := 1 + aleatoire.Intn(5); k > 0; k-- {
			motDePasse.WriteString(morceaux[aleatoire.Intn(len(morceaux))])
		}
		if !utf8.ValidString(motDePasse.String()) {
			t.Fatalf("corpus invalide : %q", motDePasse.String())
		}
		verifierSequence(t, motDePasse.String())
		if t.Failed() {
			t.Fatalf("arrêt au mot de passe n°%d", n+1)
		}
	}
}

// Le motif répété suit la même convention : « ééé » dans « chloééé! » couvre
// les octets 4 à 9 (J = dernier octet), compte 3 répétitions, et la recherche
// reprend juste après (deuxième « ééé » de « éééxééé » trouvé).
func TestRepetitionMultiOctet(t *testing.T) {
	for _, cas := range []struct {
		motDePasse string
		attendus   [][2]int // positions I, J des motifs « ééé »
	}{
		{"chloééé!", [][2]int{{4, 9}}},
		{"éééxééé", [][2]int{{0, 5}, {7, 12}}},
	} {
		t.Run(cas.motDePasse, func(t *testing.T) {
			var trouves [][2]int
			for _, m := range matching.OmnimatchAvec(cas.motDePasse, nil, charger()) {
				if m.Pattern != "repeat" {
					continue
				}
				trouves = append(trouves, [2]int{m.I, m.J})
				if m.Token != cas.motDePasse[m.I:m.J+1] || m.RepeatCount != 3 {
					t.Errorf("répétition %q en %d-%d, %d fois ; attendu le morceau couvert, 3 fois",
						m.Token, m.I, m.J, m.RepeatCount)
				}
			}
			if !reflect.DeepEqual(trouves, cas.attendus) {
				t.Errorf("répétitions en %v, attendues en %v", trouves, cas.attendus)
			}
		})
	}
}

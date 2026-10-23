package zxcvbn

import (
	"math"
	"strings"
	"testing"

	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"
	"chiffremento-cli/internal/zxcvbn/matching"
)

// seuilFaible : même valeur que bitsFaible dans tui.go (le paquet main n'est
// pas importable d'ici). Sous ce seuil, l'interface annonce « faible ».
const seuilFaible = 35

func bitsDe(p string) float64 {
	return math.Log2(PasswordStrength(p, nil).Guesses)
}

// Un mot français courant, un prénom ou un nom de famille doivent être annoncés
// faibles : majuscules, accents et année collée comprises. Le seuil seul ne
// prouve rien (la plupart de ces mots sont déjà faibles avec l'anglais) : la
// séquence retenue doit commencer par le dictionnaire français attendu, au
// rang de la forme en minuscules.
func TestMotFrancaisFaible(t *testing.T) {
	fixerAnneeReference(t, anneeReferenceParite)
	for _, cas := range []struct{ motDePasse, dictionnaire, minuscules string }{
		{"soleil", "", ""},
		{"abandon", "", ""},
		{"helene1990", "", ""},
		{"marie", frequency.NomPrenomsFr, "marie"},
		{"hélène1990", frequency.NomPrenomsFr, "hélène"},
		{"Françoise", frequency.NomPrenomsFr, "françoise"},
		{"dupont", frequency.NomNomsFr, "dupont"},
		{"DUPONT", frequency.NomNomsFr, "dupont"},
		{"Martin", frequency.NomNomsFr, "martin"},
	} {
		t.Run(cas.motDePasse, func(t *testing.T) {
			if bits := bitsDe(cas.motDePasse); bits >= seuilFaible {
				t.Errorf("%q : %.1f bits, moins de %d attendus", cas.motDePasse, bits, seuilFaible)
			}
			if cas.dictionnaire == "" {
				return
			}
			premier := PasswordStrength(cas.motDePasse, nil).Sequence[0]
			if premier.Pattern != "dictionary" || premier.DictionaryName != cas.dictionnaire {
				t.Fatalf("premier motif %q du dictionnaire %q ; attendu dictionary, %s",
					premier.Pattern, premier.DictionaryName, cas.dictionnaire)
			}
			if rang := rangDans(t, cas.minuscules, cas.dictionnaire); premier.Rank != rang {
				t.Errorf("rang %d, attendu %d (celui de %q)", premier.Rank, rang, cas.minuscules)
			}
		})
	}
}

// correspondance cherche, parmi tous les motifs trouvés (pas seulement la
// séquence retenue), le mot du dictionnaire nom qui couvre motDePasse[i:j+1].
func correspondance(motDePasse, nom string, i, j int) *match.Match {
	for _, m := range matching.OmnimatchAvec(motDePasse, nil, charger()) {
		if m.Pattern == "dictionary" && m.DictionaryName == nom && m.I == i && m.J == j {
			return m
		}
	}
	return nil
}

// rangDans rend le rang de mot (tel quel, entier) dans le dictionnaire nom.
func rangDans(t *testing.T, mot, nom string) int {
	t.Helper()
	m := correspondance(mot, nom, 0, len(mot)-1)
	if m == nil {
		t.Fatalf("%q absent de %s", mot, nom)
	}
	return m.Rank
}

// R-PHR-08 : le fichier de l'Insee écrit les noms sans accent. Tapés avec
// leurs accents, ils doivent être reconnus au même rang, et le motif doit
// couvrir la saisie d'origine (positions en octets, jeton inchangé).
func TestNomsAccentuesReconnus(t *testing.T) {
	for _, cas := range []struct{ motDePasse, sansAccent string }{
		{"lefèvre", "lefevre"},
		{"Hébert", "hebert"},
		{"ménard", "menard"},
	} {
		t.Run(cas.motDePasse, func(t *testing.T) {
			m := correspondance(cas.motDePasse, frequency.NomNomsFr, 0, len(cas.motDePasse)-1)
			if m == nil {
				t.Fatalf("%q non reconnu dans %s", cas.motDePasse, frequency.NomNomsFr)
			}
			if m.Token != cas.motDePasse || m.MatchedWord != cas.sansAccent {
				t.Errorf("jeton %q, mot %q ; attendus %q, %q", m.Token, m.MatchedWord, cas.motDePasse, cas.sansAccent)
			}
			if rang := rangDans(t, cas.sansAccent, frequency.NomNomsFr); m.Rank != rang {
				t.Errorf("rang %d, attendu %d (celui de %q)", m.Rank, rang, cas.sansAccent)
			}
		})
	}
}

// La recherche sans accent ne doit pas fabriquer de faux motifs l33t : dans
// « lefèvre1 », « lefèvre » ne contient aucune substitution (le « 1 » est
// hors du jeton), il ne doit donc pas ressortir marqué l33t.
func TestSansAccentPasDeFauxL33t(t *testing.T) {
	for _, m := range matching.OmnimatchAvec("lefèvre1", nil, charger()) {
		if m.L33t && len(m.Sub) == 0 {
			t.Errorf("motif l33t sans substitution : jeton %q, mot %q, dictionnaire %s", m.Token, m.MatchedWord, m.DictionaryName)
		}
	}
}

// Une saisie collée depuis le Finder arrive décomposée (NFD) : « é » y est un
// « e » suivi d'un accent détaché (U+0301). Elle doit valoir la forme composée.
func TestPrenomDecomposeReconnu(t *testing.T) {
	fixerAnneeReference(t, anneeReferenceParite)
	const (
		compose   = "Hélène1990"
		decompose = "He\u0301le\u0300ne1990"
		prenom    = "He\u0301le\u0300ne"
	)
	if correspondance(decompose, frequency.NomPrenomsFr, 0, len(prenom)-1) == nil {
		t.Fatalf("%q (NFD) non reconnu dans %s", prenom, frequency.NomPrenomsFr)
	}
	if ecart := math.Abs(bitsDe(decompose) - bitsDe(compose)); ecart > 1 {
		t.Errorf("NFD %.1f bits, NFC %.1f bits : même valeur attendue", bitsDe(decompose), bitsDe(compose))
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

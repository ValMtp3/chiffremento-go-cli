package frequency

import "testing"

func TestSansAccent(t *testing.T) {
	for entree, attendu := range map[string]string{
		"élève": "eleve", "où": "ou", "noël": "noel", "maïs": "mais", "garçon": "garcon",
		"cœur": "coeur", "æon": "aeon", "ÿ": "y", "plain": "plain", "ñandu": "ñandu",
		// Saisie décomposée (NFD) : accents détachés retirés.
		"he\u0301le\u0300ne": "helene", "noe\u0308l": "noel",
	} {
		if got := SansAccent(entree); got != attendu {
			t.Errorf("SansAccent(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
}

func TestRecomposer(t *testing.T) {
	for entree, attendu := range map[string]string{
		"he\u0301le\u0300ne": "hélène", "franc\u0327oise": "françoise", "noe\u0308l": "noël",
		"hélène": "hélène", "plain": "plain", "n\u0303": "n\u0303",
	} {
		if got := Recomposer(entree); got != attendu {
			t.Errorf("Recomposer(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
}

func TestSansAccentASCIISansAllocation(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() { _ = SansAccent("lefevre1990") }); n != 0 {
		t.Errorf("%v allocation(s) pour un mot ASCII, 0 attendue", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = Recomposer("hélène1990") }); n != 0 {
		t.Errorf("%v allocation(s) pour un mot sans accent détaché, 0 attendue", n)
	}
}

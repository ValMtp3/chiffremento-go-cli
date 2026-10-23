package frequency

import "testing"

func TestListesEmbarquees(t *testing.T) {
	attendu := []struct {
		nom     string
		taille  int
		premier string
	}{
		{"passwords", 30000, "123456"},
		{"english_wikipedia", 30000, "the"},
		{"female_names", 3712, "mary"},
		{"surnames", 10000, "smith"},
		{"us_tv_and_film", 19160, "you"},
		{"male_names", 983, "james"},
	}

	listes := Anglais()
	if len(listes) != len(attendu) {
		t.Fatalf("%d listes, %d attendues", len(listes), len(attendu))
	}
	for _, a := range attendu {
		liste, ok := listes[a.nom]
		if !ok {
			t.Errorf("liste %q absente", a.nom)
			continue
		}
		if len(liste.Mots) != a.taille {
			t.Errorf("%s : %d mots, %d attendus", a.nom, len(liste.Mots), a.taille)
			continue
		}
		if liste.Mots[0] != a.premier {
			t.Errorf("%s : premier mot %q, %q attendu", a.nom, liste.Mots[0], a.premier)
		}
		if liste.RangFixe != 0 {
			t.Errorf("%s : RangFixe %d, 0 attendu (rang suit l'ordre)", a.nom, liste.RangFixe)
		}
	}
}

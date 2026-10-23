package frequency

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

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

// messagePanique appelle decoder et renvoie le message de la panique ("" si aucune).
func messagePanique(fsys fs.FS) (message string) {
	defer func() {
		if r := recover(); r != nil {
			message = fmt.Sprint(r)
		}
	}()
	decoder(fsys)
	return ""
}

func TestDecoderPaniqueSurDonneesCorrompues(t *testing.T) {
	cas := []struct {
		nom     string
		fsys    fs.FS
		attendu []string
	}{
		{
			nom:     "fichier zst invalide",
			fsys:    fstest.MapFS{"listes/casse.txt.zst": {Data: []byte("ceci n'est pas du zstd")}},
			attendu: []string{"frequency : décodage de casse.txt.zst"},
		},
		{
			nom:     "dossier listes absent",
			fsys:    fstest.MapFS{},
			attendu: []string{"frequency : dossier listes embarqué illisible"},
		},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			message := messagePanique(c.fsys)
			if message == "" {
				t.Fatal("aucune panique")
			}
			for _, morceau := range c.attendu {
				if !strings.Contains(message, morceau) {
					t.Errorf("message %q ne contient pas %q", message, morceau)
				}
			}
		})
	}
}

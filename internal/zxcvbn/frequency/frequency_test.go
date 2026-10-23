package frequency

import (
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/klauspost/compress/zstd"
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

func fsAvecListe(t *testing.T, nom, texte string) fs.FS {
	t.Helper()
	encodeur, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encodeur.Close()
	return fstest.MapFS{"listes/" + nom + ".txt.zst": {Data: encodeur.EncodeAll([]byte(texte), nil)}}
}

// Une ligne qui commence par une tabulation est la variante sans accent de la
// ligne d'avant : même rang, et la tabulation ne fait pas partie du mot.
func TestDecoderVariantesAuMemeRang(t *testing.T) {
	liste := decoder(fsAvecListe(t, "prenoms", "hélène\n\thelene\njean\n\tjean2\nzoé\n"))["prenoms"]
	if want := []string{"hélène", "helene", "jean", "jean2", "zoé"}; !reflect.DeepEqual(liste.Mots, want) {
		t.Errorf("mots %q, attendu %q", liste.Mots, want)
	}
	if want := []int{1, 1, 2, 2, 3}; !reflect.DeepEqual(liste.Rangs, want) {
		t.Errorf("rangs %v, attendu %v", liste.Rangs, want)
	}
}

func TestDecoderSansVariantesPasDeRangs(t *testing.T) {
	liste := decoder(fsAvecListe(t, "plain", "un\ndeux\n"))["plain"]
	if liste.Rangs != nil {
		t.Errorf("rangs %v, nil attendu : le rang suit l'ordre", liste.Rangs)
	}
}

func TestDecoderFiltreParNom(t *testing.T) {
	fsys := fstest.MapFS{}
	for _, nom := range []string{"a", "b"} {
		for chemin, f := range fsAvecListe(t, nom, nom+"\n").(fstest.MapFS) {
			fsys[chemin] = f
		}
	}
	got := decoder(fsys, "a")
	if _, ok := got["a"]; !ok || len(got) != 1 {
		t.Errorf("listes %v, seule « a » attendue", got)
	}
}

func TestDecoderListeDemandeeAbsentePanique(t *testing.T) {
	message := ""
	func() {
		defer func() { message = fmt.Sprint(recover()) }()
		decoder(fsAvecListe(t, "a", "x\n"), "a", "manquante")
	}()
	if !strings.Contains(message, "frequency : liste manquante absente") {
		t.Errorf("message %q", message)
	}
}

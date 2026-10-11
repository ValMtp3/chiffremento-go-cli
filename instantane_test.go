package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Le dossier source est photographié avant le chiffrement et comparé juste
// avant de l'effacer. Sans ça, un fichier ajouté ou modifié pendant le
// chiffrement — ou pendant que l'utilisateur lit la question — disparaissait
// avec le reste sans avoir jamais été archivé.

func TestVerifierInchange(t *testing.T) {
	cas := []struct {
		nom      string
		modifier func(t *testing.T, racine string)
		attendu  string // vide : aucun changement attendu
	}{
		{"rien ne bouge", func(*testing.T, string) {}, ""},
		{"fichier ajouté", func(t *testing.T, r string) {
			ecrire(t, filepath.Join(r, "sous", "nouveau.txt"), []byte("jamais archivé"))
		}, "nouveau.txt"},
		{"fichier retiré", func(t *testing.T, r string) {
			if err := os.Remove(filepath.Join(r, "a.txt")); err != nil {
				t.Fatal(err)
			}
		}, "a.txt"},
		{"taille changée", func(t *testing.T, r string) {
			ecrire(t, filepath.Join(r, "a.txt"), []byte("contenu plus long qu'avant"))
		}, "a.txt"},
		{"même taille, date changée", func(t *testing.T, r string) {
			plusTard := time.Now().Add(time.Hour)
			if err := os.Chtimes(filepath.Join(r, "sous", "b.txt"), plusTard, plusTard); err != nil {
				t.Fatal(err)
			}
		}, "b.txt"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			racine := t.TempDir()
			if err := os.MkdirAll(filepath.Join(racine, "sous"), 0755); err != nil {
				t.Fatal(err)
			}
			ecrire(t, filepath.Join(racine, "a.txt"), []byte("aaa"))
			ecrire(t, filepath.Join(racine, "sous", "b.txt"), []byte("bbb"))

			avant, err := photographier(racine)
			if err != nil {
				t.Fatal(err)
			}
			c.modifier(t, racine)
			err = verifierInchange(avant, racine)
			if c.attendu == "" {
				if err != nil {
					t.Errorf("changement signalé à tort : %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("changement non détecté : la suppression aurait effacé des données non archivées")
			}
			if !strings.Contains(err.Error(), c.attendu) {
				t.Errorf("le message ne nomme pas %q : %v", c.attendu, err)
			}
		})
	}
}

func TestVerifierInchangeFichierSeul(t *testing.T) {
	dir := t.TempDir()
	f := ecrire(t, filepath.Join(dir, "seul.txt"), []byte("v1"))
	avant, err := photographier(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifierInchange(avant, f); err != nil {
		t.Errorf("fichier inchangé signalé : %v", err)
	}
	ecrire(t, f, []byte("version 2"))
	if err := verifierInchange(avant, f); err == nil {
		t.Error("modification d'un fichier seul non détectée")
	}
}

// TestEffacerSiInchange : le garde-fou doit être réellement branché sur
// l'effacement. Un fichier ajouté après le relevé bloque la suppression, et
// rien n'est effacé — ni l'original, ni le fichier ajouté.
func TestEffacerSiInchange(t *testing.T) {
	racine := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(racine, 0755); err != nil {
		t.Fatal(err)
	}
	ecrire(t, filepath.Join(racine, "a.txt"), []byte("archivé"))
	avant, err := photographier(racine)
	if err != nil {
		t.Fatal(err)
	}
	ajoute := ecrire(t, filepath.Join(racine, "tardif.txt"), []byte("jamais archivé"))

	err = effacerSiInchange(avant, racine, "source.chto", true)
	if err == nil {
		t.Fatal("suppression acceptée alors que la source a changé")
	}
	if !strings.Contains(err.Error(), "tardif.txt") {
		t.Errorf("le message ne nomme pas le fichier ajouté : %v", err)
	}
	if _, err := os.Stat(ajoute); err != nil {
		t.Errorf("le fichier non archivé a disparu : %v", err)
	}

	// Source revenue à l'état du relevé : l'effacement a lieu.
	if err := os.Remove(ajoute); err != nil {
		t.Fatal(err)
	}
	if err := effacerSiInchange(avant, racine, "source.chto", true); err != nil {
		t.Fatalf("source inchangée refusée : %v", err)
	}
	if _, err := os.Stat(racine); err == nil {
		t.Error("la source inchangée n'a pas été effacée")
	}
}

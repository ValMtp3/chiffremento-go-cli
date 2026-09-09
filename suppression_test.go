package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompterFichiers : le nombre annoncé dans la question est celui des
// fichiers, pas des entrées — un dossier vide ne compte pas pour un.
func TestCompterFichiers(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sous", "encore"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, nom := range []string{"a.txt", "sous/b.txt", "sous/encore/c.txt"} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(nom)), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	n, err := compterFichiers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("compterFichiers = %d, attendu 3", n)
	}
}

// TestSuppressionPossible garde le cas qui ferait tout perdre : chiffrer « . »
// dépose le .chto à l'intérieur du dossier proposé à la suppression, et
// répondre « supprimer » emporterait le chiffré avec l'original.
func TestSuppressionPossible(t *testing.T) {
	dir := t.TempDir()
	dedans := filepath.Join(dir, "archive"+extension)
	dehors := filepath.Join(filepath.Dir(dir), "archive"+extension)

	if raison := suppressionPossible(dir, dedans, true); raison == "" {
		t.Error("la suppression est proposée alors que le chiffré est dans le dossier à effacer")
	} else if !strings.Contains(string(raison), "intérieur") {
		t.Errorf("raison peu claire: %q", raison)
	}

	if raison := suppressionPossible(dir, dehors, true); raison != "" {
		t.Errorf("suppression refusée à tort pour un chiffré posé à côté: %q", raison)
	}

	// Un fichier ne peut rien contenir : la question se pose toujours.
	fichier := filepath.Join(dir, "note.txt")
	if raison := suppressionPossible(fichier, fichier+extension, false); raison != "" {
		t.Errorf("suppression refusée à tort pour un fichier: %q", raison)
	}
}

func TestContient(t *testing.T) {
	sep := string(os.PathSeparator)
	racine := filepath.Join(sep+"tmp", "photos")

	cas := []struct {
		nom   string
		cible string
		want  bool
	}{
		{"le dossier lui-même", racine, true},
		{"un fichier dedans", filepath.Join(racine, "a.jpg"), true},
		{"un fichier plus profond", filepath.Join(racine, "2024", "a.jpg"), true},
		{"un voisin", filepath.Join(sep+"tmp", "photos.chto"), false},
		{"un nom qui commence pareil", filepath.Join(sep+"tmp", "photos-bis", "a.jpg"), false},
		{"le parent", sep + "tmp", false},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			got, err := contient(racine, c.cible)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("contient(%q, %q) = %v, attendu %v", racine, c.cible, got, c.want)
			}
		})
	}
}

// TestLibelleSuppression : la question doit nommer ce qui disparaît, et dire ce
// que « supprimer » ne fait pas — les données restent sur le support.
func TestLibelleSuppression(t *testing.T) {
	dir := t.TempDir()
	fichier := filepath.Join(dir, "rapport.pdf")
	if err := os.WriteFile(fichier, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	titre, detail := libelleSuppression(fichier, false)
	if !strings.Contains(titre, "rapport.pdf") {
		t.Errorf("le titre ne nomme pas le fichier: %q", titre)
	}
	if !strings.Contains(detail, "support") {
		t.Errorf("le détail ne dit pas que les données restent sur le support: %q", detail)
	}

	titre, _ = libelleSuppression(dir, true)
	if !strings.Contains(titre, "1 fichiers") {
		t.Errorf("le titre d'un dossier n'annonce pas ce qu'il contient: %q", titre)
	}
}

func TestEffacer(t *testing.T) {
	dir := t.TempDir()
	fichier := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(fichier, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := effacer(fichier, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(fichier); err == nil {
		t.Error("le fichier est toujours là")
	}

	arbo := filepath.Join(dir, "arbo")
	if err := os.MkdirAll(filepath.Join(arbo, "sous"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := effacer(arbo, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(arbo); err == nil {
		t.Error("l'arborescence est toujours là")
	}

	// Un échec doit remonter : l'appelant en fait une erreur, pas un silence.
	if err := effacer(filepath.Join(dir, "absent.txt"), false); err == nil {
		t.Error("aucune erreur sur un fichier absent")
	}
}

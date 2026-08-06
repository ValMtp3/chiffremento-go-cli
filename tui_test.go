package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFormulaireSeConstruit vérifie que le formulaire principal se monte sans
// panique avec le thème appliqué.
//
// Le piloter avec des touches simulées n'est pas fiable hors d'un vrai
// terminal : sans pty, huh reste en attente. La vérification du comportement
// clavier se fait donc à la main, en lançant `chiffremento` sans argument.
func TestFormulaireSeConstruit(t *testing.T) {
	action, path := "enc", ""
	if f := mainForm(&action, &path); f == nil {
		t.Fatal("mainForm a renvoyé nil")
	}
	if th := formTheme(); th == nil {
		t.Fatal("formTheme a renvoyé nil")
	}
}

func TestValidateTarget(t *testing.T) {
	dir := t.TempDir()
	clair := filepath.Join(dir, "doc.txt")
	chiffre := filepath.Join(dir, "doc.txt.chto")
	for _, p := range []string{clair, chiffre} {
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name    string
		path    string
		action  string
		wantErr bool
	}{
		{"fichier clair à chiffrer", clair, "enc", false},
		{"fichier chiffré à déchiffrer", chiffre, "dec", false},
		{"déjà chiffré, on veut chiffrer", chiffre, "enc", true},
		{"pas de .chto, on veut déchiffrer", clair, "dec", true},
		{"fichier absent", filepath.Join(dir, "fantome.txt"), "enc", true},
		{"répertoire", dir, "enc", true},
		{"chemin vide", "", "enc", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateTarget(c.path, c.action)
			if (err != nil) != c.wantErr {
				t.Errorf("validateTarget(%q, %q) = %v, erreur attendue: %v", c.path, c.action, err, c.wantErr)
			}
		})
	}
}

func TestChooseAlgo(t *testing.T) {
	if _, err := chooseAlgo(true, true); err == nil {
		t.Error("-chacha et -parano combinés devraient être refusés")
	}
	for _, c := range []struct {
		chacha, parano bool
		want           byte
	}{
		{false, false, 1}, // aes
		{true, false, 2},  // chacha
		{false, true, 3},  // cascade
	} {
		got, err := chooseAlgo(c.chacha, c.parano)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("chooseAlgo(%v, %v) = %d, attendu %d", c.chacha, c.parano, got, c.want)
		}
	}
}

func TestCheckPaths(t *testing.T) {
	if err := checkPaths("a.txt", "a.txt"); err == nil {
		t.Error("une source identique à la destination devrait être refusée")
	}
	if err := checkPaths("./a.txt", "a.txt"); err == nil {
		t.Error("les chemins équivalents devraient être détectés")
	}
	if err := checkPaths("a.txt", "a.txt.chto"); err != nil {
		t.Errorf("chemins distincts refusés à tort: %v", err)
	}
}

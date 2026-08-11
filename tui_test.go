package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFormulaireSeConstruit vérifie que le formulaire principal se monte sans
// panique avec le thème appliqué.
//
// Le piloter avec des touches simulées n'est pas fiable hors d'un vrai
// terminal : sans pty, huh reste en attente. La vérification du comportement
// clavier se fait donc à la main, en lançant `chiffremento` sans argument.
func TestFormulaireSeConstruit(t *testing.T) {
	action, path, mode := "enc", "", "saisie"
	if f := mainForm(&action, &path, &mode); f == nil {
		t.Fatal("mainForm a renvoyé nil")
	}
	// Le second chemin de saisie monte l'explorateur de fichiers : il ne doit
	// pas paniquer non plus, thème appliqué.
	mode = "parcourir"
	if f := mainForm(&action, &path, &mode); f == nil {
		t.Fatal("mainForm a renvoyé nil avec l'explorateur")
	}
	if f := filePickerField(&action, &path); f == nil {
		t.Fatal("filePickerField a renvoyé nil")
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
		{"dossier à chiffrer", dir, "enc", false},
		{"dossier avec séparateur final", dir + string(os.PathSeparator), "enc", false},
		{"dossier à déchiffrer", dir, "dec", true},
		{"dossier à vérifier", dir, "verify", true},
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

// TestTrimTrailingSeparator : un dossier glissé dans le terminal arrive souvent
// avec un séparateur final, qui donnerait une sortie nommée « photos/.chto ».
func TestTrimTrailingSeparator(t *testing.T) {
	sep := string(os.PathSeparator)
	cases := []struct{ in, want string }{
		{"photos" + sep, "photos"},
		{"photos" + sep + sep, "photos"},
		{sep + "tmp" + sep + "a" + sep, sep + "tmp" + sep + "a"},
		{"photos", "photos"},
		{sep, sep},
	}
	for _, c := range cases {
		if got := trimTrailingSeparator(c.in); got != c.want {
			t.Errorf("trimTrailingSeparator(%q) = %q, attendu %q", c.in, got, c.want)
		}
	}
}

// TestIndicateurDeForceDictionnaire : le cas qui échappait à l'estimation
// combinatoire de la v2.0. « azerty123 » y passait pour un mot de passe à ~60
// bits, donc « correct » ; zxcvbn le reconnaît comme une suite de touches
// suivie d'un compteur.
func TestIndicateurDeForceDictionnaire(t *testing.T) {
	faibles := []string{"azerty123", "password1", "motdepasse", "Bonjour2024!", "aaaaaaaaaaaa", "p@ssw0rd"}
	for _, pw := range faibles {
		bits := passwordEntropy(pw)
		if bits >= bitsFaible {
			t.Errorf("%q évalué à %.0f bits, attendu moins de %d", pw, bits, bitsFaible)
		}
		if !strings.Contains(strengthHint(pw), "faible") {
			t.Errorf("%q n'est pas annoncé comme faible: %s", pw, strengthHint(pw))
		}
	}

	solides := []string{"tR7#vq2Lm!9zXw4Ke", "girafe-clavier-nuage-71-tempete"}
	for _, pw := range solides {
		bits := passwordEntropy(pw)
		if bits < bitsCorrect {
			t.Errorf("%q évalué à %.0f bits, attendu au moins %d", pw, bits, bitsCorrect)
		}
	}

	// À longueur égale, une saisie qui suit un motif connu doit être notée sous
	// une saisie aléatoire : c'est tout l'apport du dictionnaire.
	if passwordEntropy("azertyuiopqs") >= passwordEntropy("x7Qv2mKp9Lzt") {
		t.Error("un motif de clavier est évalué aussi haut qu'une saisie aléatoire de même longueur")
	}
}

func TestStrengthHintVide(t *testing.T) {
	if got := strengthHint(""); !strings.Contains(got, "jamais affiché") {
		t.Errorf("aide inattendue pour une saisie vide: %q", got)
	}
	if bits := passwordEntropy(""); bits != 0 {
		t.Errorf("passwordEntropy(\"\") = %v, attendu 0", bits)
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

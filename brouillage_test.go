package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nomHexadecimal : 8 octets tirés au hasard, donc 16 caractères hexadécimaux.
var nomHexadecimal = regexp.MustCompile(`^[0-9a-f]{16}\` + extension + `$`)

// TestNomBrouille : le nom de sortie ne doit rien dire de la source, mais rester
// dans son dossier — le chiffré se retrouve là où on l'a fabriqué.
func TestNomBrouille(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "rapport-medical.pdf")
	if err := os.WriteFile(source, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := nomBrouille(source)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Dir(out); got != dir {
		t.Errorf("le chiffré sort dans %q, attendu le dossier de la source %q", got, dir)
	}
	base := filepath.Base(out)
	if !nomHexadecimal.MatchString(base) {
		t.Errorf("nom de sortie %q, attendu 16 caractères hexadécimaux suivis de %s", base, extension)
	}
	if strings.Contains(base, "rapport") || strings.Contains(base, "medical") {
		t.Errorf("le nom de sortie %q laisse filtrer celui de la source", base)
	}
	if _, err := os.Lstat(out); err == nil {
		t.Errorf("le nom de sortie %q désigne un fichier déjà là", out)
	}

	// Deux chiffrements du même fichier ne doivent pas produire le même nom :
	// sinon le second écraserait le premier, et le nom redeviendrait un lien
	// entre le chiffré et sa source.
	autre, err := nomBrouille(source)
	if err != nil {
		t.Fatal(err)
	}
	if autre == out {
		t.Errorf("deux tirages ont donné le même nom %q", out)
	}
}

// TestBrouillerDate : la date de modification est celle du 1er janvier 2000,
// et non celle de l'écriture.
func TestBrouillerDate(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "7f3a9c21"+extension)
	if err := os.WriteFile(chemin, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := brouillerDate(chemin); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().UTC().Equal(dateNeutre) {
		t.Errorf("date de modification %s, attendu %s", info.ModTime().UTC(), dateNeutre)
	}
}

// TestBrouillerDateFichierAbsent : l'échec doit remonter, jamais passer pour un
// succès — l'appelant en fait un avertissement visible, sans quoi l'utilisateur
// croirait sa date masquée alors qu'elle ne l'est pas.
func TestBrouillerDateFichierAbsent(t *testing.T) {
	if err := brouillerDate(filepath.Join(t.TempDir(), "absent.chto")); err == nil {
		t.Error("aucune erreur sur un fichier absent")
	}
}

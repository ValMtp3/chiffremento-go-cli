//go:build !windows

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/creack/pty"
)

// TestReadPasswordDepuisTTY couvre le chemin ouvert par -in - : l'entrée
// standard porte les données, donc le mot de passe doit venir du terminal.
//
// Le test compte autant pour ce qu'il vérifie que pour ce qu'il empêche : sans
// ce chemin, la première ligne des données serait lue comme mot de passe et le
// reste chiffré avec un secret involontaire.
func TestReadPasswordDepuisTTY(t *testing.T) {
	maitre, esclave, err := pty.Open()
	if err != nil {
		t.Skipf("pseudo-terminal indisponible ici: %v", err)
	}
	defer maitre.Close()
	nom := esclave.Name()
	esclave.Close()

	precedent := ttyDevice
	ttyDevice = nom
	defer func() { ttyDevice = precedent }()

	// Les données occupent l'entrée standard : si readPassword s'y trompait, il
	// lirait « données confidentielles » comme mot de passe.
	stdin := os.Stdin
	defer func() { os.Stdin = stdin }()
	faux, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer faux.Close()
	os.Stdin = faux

	go func() {
		maitre.WriteString("motdepassetube\n")
		maitre.WriteString("motdepassetube\n")
	}()

	pw, err := readPassword(true, true)
	if err != nil {
		t.Fatalf("lecture du mot de passe sur le terminal: %v", err)
	}
	if string(pw) != "motdepassetube" {
		t.Errorf("mot de passe lu %q, attendu %q", pw, "motdepassetube")
	}
}

// TestReadPasswordSansTTY : sans terminal de contrôle, il faut échouer en le
// disant, jamais consommer les données.
func TestReadPasswordSansTTY(t *testing.T) {
	precedent := ttyDevice
	ttyDevice = filepathJoinInexistant(t)
	defer func() { ttyDevice = precedent }()

	_, err := readPassword(false, true)
	if err == nil {
		t.Fatal("aucune erreur alors que le terminal est introuvable")
	}
	if !strings.Contains(err.Error(), "-in FICHIER") {
		t.Errorf("l'erreur ne propose pas d'alternative : %v", err)
	}
}

func filepathJoinInexistant(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/pas-un-terminal"
}

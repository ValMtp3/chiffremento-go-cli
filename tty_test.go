//go:build !windows

package main

import (
	"os"
	"strings"
	"testing"
	"time"

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
	// L'esclave reste ouvert pour toute la durée du test. Le fermer libère le
	// pseudo-terminal sur macOS : la réouverture par son nom réussit, mais plus
	// aucune donnée écrite sur le maître n'arrive, et la lecture attend
	// indéfiniment. Sous Linux le tampon survivait, d'où un test vert en CI et
	// un blocage de dix minutes en local.
	defer esclave.Close()

	precedent := ttyDevice
	ttyDevice = esclave.Name()
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

	// term.ReadPassword bascule le terminal en mode brut avant de lire. On écrit
	// donc en boucle plutôt qu'une seule fois : une écriture arrivée trop tôt
	// serait consommée par la discipline de ligne encore active.
	fini := make(chan struct{})
	defer close(fini)
	go func() {
		for {
			select {
			case <-fini:
				return
			default:
			}
			maitre.WriteString("motdepassetube\n")
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Garde-fou : sans lui, une régression sur ce chemin bloque la suite
	// jusqu'au timeout global de dix minutes au lieu d'échouer tout de suite.
	type resultat struct {
		pw  []byte
		err error
	}
	res := make(chan resultat, 1)
	go func() {
		pw, err := readPassword(true, true)
		res <- resultat{pw, err}
	}()

	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("lecture du mot de passe sur le terminal: %v", r.err)
		}
		if string(r.pw) != "motdepassetube" {
			t.Errorf("mot de passe lu %q, attendu %q", r.pw, "motdepassetube")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("readPassword n'a pas rendu la main : la saisie au terminal est bloquée")
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

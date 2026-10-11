//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"chiffremento-cli/pkg"
)

// Destinations spéciales du chemin des flux. Avant l'écriture atomique,
// openDest ouvrait la destination et écrivait dedans : `-out /dev/null`
// servait à vérifier un flux sans rien garder, un tube nommé passait les
// octets à un autre programme, un lien symbolique écrivait dans sa cible.
// Un rename les remplacerait par un fichier ordinaire — ou échouerait,
// faute de droits sur /dev.

func TestFluxVersDevNull(t *testing.T) {
	dir := t.TempDir()
	chto := chiffreDeTest(t, dir)
	avecEntree(t, chto)
	if _, err := decryptTo("-", os.DevNull, []byte(motDePasseTest), true); err != nil {
		t.Fatalf("déchiffrement vers %s : %v", os.DevNull, err)
	}
	st, err := os.Lstat(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		t.Fatalf("%s n'est plus un périphérique : %v", os.DevNull, st.Mode())
	}
}

func TestFluxVersTubeNomme(t *testing.T) {
	dir := t.TempDir()
	tube := filepath.Join(dir, "tube")
	if err := syscall.Mkfifo(tube, 0600); err != nil {
		t.Skipf("mkfifo indisponible : %v", err)
	}
	recu := make(chan int64, 1)
	go func() {
		f, err := os.Open(tube)
		if err != nil {
			recu <- -1
			return
		}
		defer f.Close()
		n, _ := io.Copy(io.Discard, f)
		recu <- n
	}()

	source := ecrire(t, filepath.Join(dir, "source.txt"), []byte("vers un tube"))
	avecEntree(t, source)
	if err := encryptTo("-", tube, []byte(motDePasseTest), pkg.Options{Algo: pkg.AlgoAES, Force: true}); err != nil {
		t.Fatalf("chiffrement vers un tube nommé : %v", err)
	}
	select {
	case n := <-recu:
		if n <= 0 {
			t.Errorf("le lecteur du tube a reçu %d octets", n)
		}
	case <-time.After(10 * time.Second):
		// Le tube a été remplacé : son lecteur attend un écrivain qui ne
		// viendra jamais. On le débloque en ouvrant le tube nous-mêmes.
		if f, err := os.OpenFile(tube, os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		t.Error("rien n'a été écrit dans le tube nommé")
	}
	st, err := os.Lstat(tube)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("le tube a été remplacé par un fichier ordinaire : %v", st.Mode())
	}
}

func TestFluxVersLienSymbolique(t *testing.T) {
	dir := t.TempDir()
	chto := chiffreDeTest(t, dir)
	cible := ecrire(t, filepath.Join(dir, "cible.txt"), []byte("ancien contenu"))
	lien := filepath.Join(dir, "lien.txt")
	if err := os.Symlink(cible, lien); err != nil {
		t.Fatal(err)
	}

	avecEntree(t, chto)
	if _, err := decryptTo("-", lien, []byte(motDePasseTest), true); err != nil {
		t.Fatalf("déchiffrement vers un lien : %v", err)
	}
	st, err := os.Lstat(lien)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Error("le lien symbolique a été remplacé par un fichier")
	}
	if got, _ := os.ReadFile(cible); string(got) != "contenu secret" {
		t.Errorf("la cible du lien contient %q", got)
	}
}

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"chiffremento-cli/pkg"
)

// Tests de l'écriture vers un fichier quand l'autre côté est un flux
// (`-in - -out f.txt`). Ce chemin créait la destination avec os.Create avant
// d'avoir lu l'en-tête : un mauvais mot de passe avec -force vidait un fichier
// existant, et le clair partiel restait en 0644.

// chiffreDeTest produit un .chto pour les tests de flux.
func chiffreDeTest(t *testing.T, dir string) string {
	t.Helper()
	in := ecrire(t, filepath.Join(dir, "doc.txt"), []byte("contenu secret"))
	chto := filepath.Join(dir, "doc.chto")
	if err := pkg.Encrypt(in, chto, []byte(motDePasseTest), pkg.Options{Algo: pkg.AlgoAES}); err != nil {
		t.Fatal(err)
	}
	return chto
}

// temporairesRestants liste les .chto-tmp-* laissés dans dir.
func temporairesRestants(t *testing.T, dir string) []string {
	t.Helper()
	restes, err := filepath.Glob(filepath.Join(dir, ".chto-tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	return restes
}

func TestDecryptFluxMauvaisMotDePasseGardeLaDestination(t *testing.T) {
	dir := t.TempDir()
	chto := chiffreDeTest(t, dir)
	out := ecrire(t, filepath.Join(dir, "precieux.txt"), []byte("à garder"))

	avecEntree(t, chto)
	if _, err := decryptTo("-", out, []byte("mauvais"), true); err == nil {
		t.Fatal("un mauvais mot de passe a été accepté")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("la destination a disparu : %v", err)
	}
	if string(got) != "à garder" {
		t.Errorf("la destination a été modifiée avant la vérification : %q", got)
	}
	if restes := temporairesRestants(t, dir); len(restes) > 0 {
		t.Errorf("temporaires laissés après l'échec : %v", restes)
	}
}

func TestDecryptFluxMauvaisMotDePasseNeLaissePasDeFichier(t *testing.T) {
	dir := t.TempDir()
	chto := chiffreDeTest(t, dir)
	out := filepath.Join(dir, "absent.txt")

	avecEntree(t, chto)
	if _, err := decryptTo("-", out, []byte("mauvais"), false); err == nil {
		t.Fatal("un mauvais mot de passe a été accepté")
	}
	if _, err := os.Lstat(out); err == nil {
		t.Error("un fichier de sortie a été laissé alors que le déchiffrement a échoué")
	}
}

func TestDecryptFluxSortieEnClairPrivee(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pas de bits de permission POSIX sous Windows")
	}
	dir := t.TempDir()
	chto := chiffreDeTest(t, dir)
	out := filepath.Join(dir, "clair.txt")

	avecEntree(t, chto)
	if _, err := decryptTo("-", out, []byte(motDePasseTest), false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "contenu secret" {
		t.Errorf("contenu %q", got)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Errorf("clair écrit en %o, attendu 0600 : lisible par les autres comptes", perm)
	}
}

func TestEncryptFluxVersFichierAtomique(t *testing.T) {
	dir := t.TempDir()
	in := ecrire(t, filepath.Join(dir, "source.txt"), []byte("par un tube"))
	out := filepath.Join(dir, "sortie.chto")

	avecEntree(t, in)
	if err := encryptTo("-", out, []byte(motDePasseTest), pkg.Options{Algo: pkg.AlgoAES}); err != nil {
		t.Fatal(err)
	}
	if restes := temporairesRestants(t, dir); len(restes) > 0 {
		t.Errorf("temporaires laissés après un succès : %v", restes)
	}
	if err := pkg.Verify(out, []byte(motDePasseTest), pkg.Options{}); err != nil {
		t.Errorf("le chiffré écrit depuis un flux ne se relit pas : %v", err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0600 {
			t.Errorf("chiffré écrit en %o, attendu 0600", perm)
		}
	}
}

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// install.sh est lancé dans un dossier temporaire, avec un faux cosign, un
// faux sudo et un dossier d'installation jetable : rien n'est installé dans le
// vrai système, aucun accès réseau.

const (
	identiteAttendue  = "^https://github.com/ValMtp3/chiffremento-go-cli/.github/workflows/release.yml@refs/tags/v"
	emetteurAttendu   = "https://token.actions.githubusercontent.com"
	avertissementSans = "signature non vérifiée : installe cosign pour plus de sûreté"
)

type bacInstall struct {
	dossier  string // où install.sh est lancé (archive, checksums.txt)
	bin      string // faux cosign et faux sudo
	cible    string // dossier d'installation
	appels   string // arguments reçus par le faux cosign
	cheminSh string
}

// faux cosign : consigne ses arguments, un par ligne, puis sort avec le code
// et le message demandés.
func ecrireFauxCosign(t *testing.T, bin, appels string, code int, message string) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do printf '%%s\\n' \"$a\" >> %q; done\n", appels)
	if message != "" {
		script += fmt.Sprintf("echo %q >&2\n", message)
	}
	script += fmt.Sprintf("exit %d\n", code)
	ecrire(t, filepath.Join(bin, "cosign"), []byte(script))
	if err := os.Chmod(filepath.Join(bin, "cosign"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func preparerInstall(t *testing.T, avecBundle bool) bacInstall {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("install.sh ne vise pas Windows")
	}
	racine := t.TempDir()
	b := bacInstall{
		dossier: filepath.Join(racine, "dl"),
		bin:     filepath.Join(racine, "bin"),
		cible:   filepath.Join(racine, "cible"),
		appels:  filepath.Join(racine, "appels.txt"),
	}
	for _, d := range []string{b.dossier, b.bin, b.cible} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	abs, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	b.cheminSh = abs

	// Une vraie archive, listée dans un vrai checksums.txt.
	osNom, arch := runtime.GOOS, runtime.GOARCH
	nom := fmt.Sprintf("chiffremento_1.0.0_%s_%s.tar.gz", osNom, arch)
	contenu := filepath.Join(racine, "contenu")
	if err := os.MkdirAll(contenu, 0o755); err != nil {
		t.Fatal(err)
	}
	ecrire(t, filepath.Join(contenu, "chiffremento"), []byte("#!/bin/sh\necho faux\n"))
	archive := filepath.Join(b.dossier, nom)
	if sortie, err := exec.Command("tar", "-czf", archive, "-C", contenu, "chiffremento").CombinedOutput(); err != nil {
		t.Fatalf("tar : %v\n%s", err, sortie)
	}
	octets, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	ecrire(t, filepath.Join(b.dossier, "checksums.txt"),
		[]byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(octets), nom)))
	if avecBundle {
		ecrire(t, filepath.Join(b.dossier, "checksums.txt.sigstore.json"), []byte("{}"))
	}

	// Faux sudo : exécute la commande telle quelle (cp vers le dossier jetable).
	ecrire(t, filepath.Join(b.bin, "sudo"), []byte("#!/bin/sh\nexec \"$@\"\n"))
	if err := os.Chmod(filepath.Join(b.bin, "sudo"), 0o755); err != nil {
		t.Fatal(err)
	}
	return b
}

// lancer exécute install.sh ; le PATH ne contient que le faux dossier et les
// outils système (aucun vrai cosign ne peut s'y glisser).
func (b bacInstall) lancer(t *testing.T) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", b.cheminSh)
	cmd.Dir = b.dossier
	cmd.Env = []string{
		"PATH=" + b.bin + ":/usr/bin:/bin",
		"HOME=" + b.dossier,
		"CHIFFREMENTO_INSTALL_DIR=" + b.cible,
	}
	sortie, err := cmd.CombinedOutput()
	return string(sortie), err
}

func (b bacInstall) installe() bool {
	_, err := os.Stat(filepath.Join(b.cible, "chiffremento"))
	return err == nil
}

func TestInstallSignatureValide(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 0, "")
	sortie, err := b.lancer(t)
	if err != nil {
		t.Fatalf("installation attendue : %v\n%s", err, sortie)
	}
	if !b.installe() {
		t.Fatalf("binaire absent du dossier d'installation\n%s", sortie)
	}
	if !strings.Contains(sortie, "Signature vérifiée") {
		t.Errorf("confirmation de signature absente :\n%s", sortie)
	}
}

// Review Focus 1 : l'identité exigée est exactement celle de release.yml sur
// un tag v*, pas « n'importe quel workflow GitHub ».
func TestInstallIdentitePasseeACosign(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 0, "")
	if sortie, err := b.lancer(t); err != nil {
		t.Fatalf("%v\n%s", err, sortie)
	}
	brut, err := os.ReadFile(b.appels)
	if err != nil {
		t.Fatalf("cosign n'a pas été appelé : %v", err)
	}
	attendu := []string{
		"verify-blob",
		"--bundle", "./checksums.txt.sigstore.json",
		"--certificate-identity-regexp", identiteAttendue,
		"--certificate-oidc-issuer", emetteurAttendu,
		"./checksums.txt",
	}
	obtenu := strings.Split(strings.TrimSuffix(string(brut), "\n"), "\n")
	if strings.Join(obtenu, "\n") != strings.Join(attendu, "\n") {
		t.Fatalf("arguments de cosign inattendus :\n obtenu  : %q\n attendu : %q", obtenu, attendu)
	}
}

func TestInstallSignatureFausseRefusee(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 1, "Error: none of the expected identities matched")
	sortie, err := b.lancer(t)
	if err == nil {
		t.Fatalf("refus attendu\n%s", sortie)
	}
	if b.installe() {
		t.Error("le binaire a été installé malgré une signature fausse")
	}
	if !strings.Contains(sortie, "installation refusée") {
		t.Errorf("message de refus absent :\n%s", sortie)
	}
}

// Review Focus 2 : cosign présent mais réseau absent → refus clair, pas de
// repli silencieux sur « continuer ».
func TestInstallCosignSansReseauRefuse(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 1, "Error: dial tcp: lookup tuf-repo-cdn.sigstore.dev: no such host")
	sortie, err := b.lancer(t)
	if err == nil {
		t.Fatalf("refus attendu\n%s", sortie)
	}
	if b.installe() {
		t.Error("le binaire a été installé alors que la signature n'a pas pu être vérifiée")
	}
	for _, voulu := range []string{"installation refusée", "réseau"} {
		if !strings.Contains(sortie, voulu) {
			t.Errorf("%q absent du message :\n%s", voulu, sortie)
		}
	}
}

func TestInstallSansCosignAvertitEtInstalle(t *testing.T) {
	b := preparerInstall(t, true)
	sortie, err := b.lancer(t)
	if err != nil {
		t.Fatalf("installation attendue : %v\n%s", err, sortie)
	}
	if !strings.Contains(sortie, avertissementSans) {
		t.Errorf("avertissement exact absent :\n%s", sortie)
	}
	if !b.installe() {
		t.Error("binaire absent du dossier d'installation")
	}
	if !strings.Contains(sortie, "Empreinte vérifiée") {
		t.Errorf("l'empreinte SHA-256 doit rester vérifiée :\n%s", sortie)
	}
}

func TestInstallBundleAbsentAvertitEtInstalle(t *testing.T) {
	b := preparerInstall(t, false)
	ecrireFauxCosign(t, b.bin, b.appels, 0, "")
	sortie, err := b.lancer(t)
	if err != nil {
		t.Fatalf("installation attendue : %v\n%s", err, sortie)
	}
	if !strings.Contains(sortie, "signature non vérifiée") {
		t.Errorf("avertissement absent :\n%s", sortie)
	}
	if !b.installe() {
		t.Error("binaire absent du dossier d'installation")
	}
	if _, err := os.Stat(b.appels); err == nil {
		t.Error("cosign ne doit pas être appelé sans bundle")
	}
}

// L'empreinte reste vérifiée même quand la signature est bonne.
func TestInstallEmpreinteFausseRefuseeMemeSigne(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 0, "")
	ecrire(t, filepath.Join(b.dossier, "checksums.txt"),
		[]byte(strings.Repeat("0", 64)+"  chiffremento_1.0.0_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz\n"))
	sortie, err := b.lancer(t)
	if err == nil || b.installe() {
		t.Fatalf("refus attendu\n%s", sortie)
	}
}

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	ecrireFauxCosignVersion(t, bin, appels, "v3.0.4", code, message)
}

// Même faux cosign, qui annonce la version donnée à `cosign version` (appel
// non consigné : appels ne garde que la vérification).
func ecrireFauxCosignVersion(t *testing.T, bin, appels, version string, code int, message string) {
	t.Helper()
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'GitVersion:    %s'; exit 0; fi\n", version)
	script += fmt.Sprintf("for a in \"$@\"; do printf '%%s\\n' \"$a\" >> %q; done\n", appels)
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
	return preparerInstallVersion(t, avecBundle, "1.0.0")
}

func preparerInstallVersion(t *testing.T, avecBundle bool, version string) bacInstall {
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
	nom := fmt.Sprintf("chiffremento_%s_%s_%s.tar.gz", version, osNom, arch)
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

// Cosign présent et bundle absent : refus, quelle que soit la version. Le nom
// de l'archive est modifiable par un attaquant, et sans signature
// checksums.txt ne prouve rien : on ne s'y fie donc pas pour deviner l'âge.
func TestInstallBundleAbsentRefuse(t *testing.T) {
	for _, version := range []string{"2.4.0", "2.4.0-rc1", "1.0.0", "abc", ""} {
		t.Run("archive "+version, func(t *testing.T) {
			b := preparerInstallVersion(t, false, version)
			ecrireFauxCosign(t, b.bin, b.appels, 0, "")
			sortie, err := b.lancer(t)
			if err == nil || b.installe() {
				t.Fatalf("refus attendu\n%s", sortie)
			}
			verifierMessageBundleAbsent(t, sortie)
			if _, err := os.Stat(b.appels); err == nil {
				t.Error("cosign ne doit pas être appelé sans bundle")
			}
		})
	}
}

// Même règle pour le binaire nu (make build-all) dès que checksums.txt sert.
func TestInstallBinaireNuBundleAbsentRefuse(t *testing.T) {
	b := preparerInstall(t, false)
	ecrireFauxCosign(t, b.bin, b.appels, 0, "")
	if err := os.Remove(filepath.Join(b.dossier, fmt.Sprintf("chiffremento_1.0.0_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH))); err != nil {
		t.Fatal(err)
	}
	nu := []byte("#!/bin/sh\necho nu\n")
	ecrire(t, filepath.Join(b.dossier, fmt.Sprintf("chiffremento-%s-%s", runtime.GOOS, runtime.GOARCH)), nu)
	ecrire(t, filepath.Join(b.dossier, "checksums.txt"),
		[]byte(fmt.Sprintf("%x  chiffremento-%s-%s\n", sha256.Sum256(nu), runtime.GOOS, runtime.GOARCH)))
	sortie, err := b.lancer(t)
	if err == nil || b.installe() {
		t.Fatalf("refus attendu\n%s", sortie)
	}
	verifierMessageBundleAbsent(t, sortie)
}

func verifierMessageBundleAbsent(t *testing.T, sortie string) {
	t.Helper()
	for _, voulu := range []string{"installation refusée", "checksums.txt.sigstore.json", "même page de release", "install.sh fourni avec cette release"} {
		if !strings.Contains(sortie, voulu) {
			t.Errorf("%q absent du message :\n%s", voulu, sortie)
		}
	}
}

// Cosign KO + empreinte fausse : c'est la signature qui est signalée d'abord.
func TestInstallSignatureAvantEmpreinte(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 1, "Error: signature invalide")
	ecrire(t, filepath.Join(b.dossier, "checksums.txt"),
		[]byte(strings.Repeat("0", 64)+"  chiffremento_1.0.0_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz\n"))
	sortie, err := b.lancer(t)
	if err == nil || b.installe() {
		t.Fatalf("refus attendu\n%s", sortie)
	}
	if !strings.Contains(sortie, "Signature de checksums.txt non vérifiée") {
		t.Errorf("message de signature absent :\n%s", sortie)
	}
	if strings.Contains(sortie, "Empreinte invalide") {
		t.Errorf("l'empreinte ne doit pas être examinée avant la signature :\n%s", sortie)
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

// Le script ne doit pas sortir en erreur après une installation réussie : le
// binaire nu n'a pas de dossier temporaire à nettoyer.
func TestInstallBinaireNuCodeSortieZero(t *testing.T) {
	b := preparerInstall(t, true)
	ecrireFauxCosign(t, b.bin, b.appels, 0, "")
	if err := os.Remove(filepath.Join(b.dossier, fmt.Sprintf("chiffremento_1.0.0_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH))); err != nil {
		t.Fatal(err)
	}
	nu := []byte("#!/bin/sh\necho nu\n")
	ecrire(t, filepath.Join(b.dossier, fmt.Sprintf("chiffremento-%s-%s", runtime.GOOS, runtime.GOARCH)), nu)
	ecrire(t, filepath.Join(b.dossier, "checksums.txt"),
		[]byte(fmt.Sprintf("%x  chiffremento-%s-%s\n", sha256.Sum256(nu), runtime.GOOS, runtime.GOARCH)))
	sortie, err := b.lancer(t)
	if err != nil {
		t.Fatalf("code de sortie 0 attendu après une installation réussie : %v\n%s", err, sortie)
	}
	if !b.installe() {
		t.Fatalf("binaire absent\n%s", sortie)
	}
}

// cosign trop ancien pour lire le bundle : refus clair, sans lancer la
// vérification. Seuils : 2.6.2 (v2) et 3.0.4 (v3), voir install.sh.
func TestInstallCosignVersionMinimale(t *testing.T) {
	cas := []struct {
		version string
		accepte bool
	}{
		{"v2.4.0", false},
		{"v2.5.0", false},
		{"v2.6.1", false},
		{"v2.6.2", true},
		{"v2.10.0", true},
		{"v3.0.3", false},
		{"v3.0.4", true},
		{"v3.1.0", true},
		{"devel", true}, // illisible : on laisse cosign trancher
	}
	for _, c := range cas {
		t.Run(c.version, func(t *testing.T) {
			b := preparerInstall(t, true)
			ecrireFauxCosignVersion(t, b.bin, b.appels, c.version, 0, "")
			sortie, err := b.lancer(t)
			if c.accepte {
				if err != nil || !b.installe() {
					t.Fatalf("installation attendue : %v\n%s", err, sortie)
				}
				return
			}
			if err == nil || b.installe() {
				t.Fatalf("refus attendu\n%s", sortie)
			}
			for _, voulu := range []string{"cosign trop ancien", "GHSA-whqx-f9j3-ch6m", "2.6.2", "3.0.4", "installation refusée"} {
				if !strings.Contains(sortie, voulu) {
					t.Errorf("%q absent du message :\n%s", voulu, sortie)
				}
			}
			if _, err := os.Stat(b.appels); err == nil {
				t.Error("la vérification ne doit pas être lancée avec un cosign trop ancien")
			}
		})
	}
}

// L'identité attendue est écrite à trois endroits (release.yml, install.sh,
// RELEASE.md) : ils doivent rester identiques, sinon une release signée par la
// CI serait refusée par install.sh, ou pire, l'inverse.
func TestInstallIdentiteIdentiqueDansTousLesFichiers(t *testing.T) {
	lire := func(chemin string) string {
		t.Helper()
		brut, err := os.ReadFile(chemin)
		if err != nil {
			t.Fatal(err)
		}
		return string(brut)
	}
	extraire := func(chemin, motif string) string {
		t.Helper()
		m := regexp.MustCompile(motif).FindStringSubmatch(lire(chemin))
		if m == nil {
			t.Fatalf("%s : motif %q introuvable", chemin, motif)
		}
		return m[1]
	}
	release := ".github/workflows/release.yml"
	identite := extraire(release, `IDENTITE: '([^']+)'`)
	emetteur := extraire(release, `EMETTEUR: (\S+)`)
	if identite != identiteAttendue || emetteur != emetteurAttendu {
		t.Errorf("release.yml : %q / %q, attendu %q / %q", identite, emetteur, identiteAttendue, emetteurAttendu)
	}
	if got := extraire("install.sh", `SIGNATURE_IDENTITE='([^']+)'`); got != identite {
		t.Errorf("install.sh : identité %q, release.yml : %q", got, identite)
	}
	if got := extraire("install.sh", `SIGNATURE_EMETTEUR='([^']+)'`); got != emetteur {
		t.Errorf("install.sh : émetteur %q, release.yml : %q", got, emetteur)
	}
	releaseMd := lire("RELEASE.md")
	for _, voulu := range []string{identite, emetteur} {
		if !strings.Contains(releaseMd, voulu) {
			t.Errorf("RELEASE.md ne contient pas %q", voulu)
		}
	}
}

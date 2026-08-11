package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chiffremento-cli/pkg"
)

// Tests des chemins du CLI.
//
// Ils passent par doEncrypt, doDecrypt, doVerify et doInfo — les fonctions que
// `run` appelle — et non par le binaire compilé : c'est ce qui permet de vérifier
// les erreurs et les sorties sans dépendre d'un processus externe.
//
// Deux substitutions rendent ça possible : os.Stdin porte le mot de passe (c'est
// le chemin non interactif documenté, `echo pw | chiffremento`), et os.Stdout est
// détourné vers un fichier. Elles sont globales, donc ces tests ne s'exécutent
// jamais en parallèle.

const motDePasseTest = "motdepassetest123"

// avecMotDePasse remplace l'entrée standard par une ligne contenant le mot de
// passe, comme le ferait un `echo pw | chiffremento`.
func avecMotDePasse(t *testing.T, pw string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(pw + "\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	precedent := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = precedent
		f.Close()
	})
}

// avecEntree remplace l'entrée standard par le contenu d'un fichier : c'est le
// cas de `-in -`, où les données arrivent par un tube.
func avecEntree(t *testing.T, chemin string) {
	t.Helper()
	f, err := os.Open(chemin)
	if err != nil {
		t.Fatal(err)
	}
	precedent := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = precedent
		f.Close()
	})
}

// captureSortie détourne la sortie standard vers un fichier et renvoie son
// chemin. Un fichier et non un tube : un tube de 64 Kio se remplit et bloque
// l'écrivain si personne ne lit en parallèle, ce qui figerait le test.
func captureSortie(t *testing.T) string {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "stdout")
	f, err := os.Create(chemin)
	if err != nil {
		t.Fatal(err)
	}
	precedent := os.Stdout
	os.Stdout = f
	t.Cleanup(func() {
		os.Stdout = precedent
		f.Close()
	})
	return chemin
}

func ecrire(t *testing.T, chemin string, contenu []byte) string {
	t.Helper()
	if err := os.WriteFile(chemin, contenu, 0644); err != nil {
		t.Fatal(err)
	}
	return chemin
}

// arbreCLI construit un petit dossier de test.
func arbreCLI(t *testing.T) string {
	t.Helper()
	racine := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(racine, "sous"), 0755); err != nil {
		t.Fatal(err)
	}
	ecrire(t, filepath.Join(racine, "a.txt"), []byte("premier fichier\n"))
	ecrire(t, filepath.Join(racine, "sous", "b.bin"), bytes.Repeat([]byte{0x00, 0x7f}, 2000))
	return racine
}

// --- Aiguillages de chiffrement et de déchiffrement ---------------------

func TestDoEncryptDecryptFichier(t *testing.T) {
	dir := t.TempDir()
	contenu := []byte("contenu confidentiel, accentué\n")
	in := ecrire(t, filepath.Join(dir, "doc.txt"), contenu)

	// Sortie par défaut : l'entrée suivie de l'extension.
	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, "", pkg.AlgoAES, pkg.CompNone, false); err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	if _, err := os.Stat(in + extension); err != nil {
		t.Fatalf("la sortie par défaut %s n'a pas été créée: %v", in+extension, err)
	}

	// Destination choisie au déchiffrement.
	out := filepath.Join(dir, "relu.txt")
	avecMotDePasse(t, motDePasseTest)
	if err := doDecrypt(in+extension, out); err != nil {
		t.Fatalf("déchiffrement: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contenu, got) {
		t.Error("le contenu déchiffré diffère de l'original")
	}
}

func TestDoEncryptDestinationChoisie(t *testing.T) {
	dir := t.TempDir()
	in := ecrire(t, filepath.Join(dir, "doc.txt"), []byte("x"))
	ailleurs := filepath.Join(t.TempDir(), "autre-nom.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, ailleurs, pkg.AlgoChaCha, pkg.CompZstd, false); err != nil {
		t.Fatalf("chiffrement vers une destination choisie: %v", err)
	}
	d, err := pkg.Inspect(ailleurs)
	if err != nil {
		t.Fatal(err)
	}
	if d.Algo != pkg.AlgoName(pkg.AlgoChaCha) {
		t.Errorf("algorithme %q, attendu %q", d.Algo, pkg.AlgoName(pkg.AlgoChaCha))
	}
	if d.Comp != "zstd" {
		t.Errorf("compression %q, attendu zstd", d.Comp)
	}
	// La sortie par défaut ne doit pas avoir été créée en plus.
	if _, err := os.Stat(in + extension); err == nil {
		t.Error("la sortie par défaut a été créée alors qu'une destination était donnée")
	}
}

func TestDoEncryptDecryptDossier(t *testing.T) {
	src := arbreCLI(t)
	chto := filepath.Join(t.TempDir(), "archive.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(src, chto, pkg.AlgoAES, pkg.CompZstd, false); err != nil {
		t.Fatalf("chiffrement du dossier: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "restaure")
	avecMotDePasse(t, motDePasseTest)
	if err := doDecrypt(chto, dst); err != nil {
		t.Fatalf("déchiffrement du dossier: %v", err)
	}
	for rel, attendu := range map[string]string{
		"a.txt": "premier fichier\n",
	} {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil {
			t.Errorf("lecture de %s: %v", rel, err)
			continue
		}
		if string(got) != attendu {
			t.Errorf("%s : contenu %q, attendu %q", rel, got, attendu)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "sous", "b.bin")); err != nil {
		t.Errorf("sous/b.bin manque: %v", err)
	}
}

// TestDoEncryptDossierSeparateurFinal : c'est le cas du glisser-déposer, où le
// chemin arrive avec un séparateur final. Sans normalisation, la sortie
// s'appellerait « source/.chto », un fichier caché dans le dossier chiffré.
func TestDoEncryptDossierSeparateurFinal(t *testing.T) {
	src := arbreCLI(t)

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(src+string(os.PathSeparator), "", pkg.AlgoAES, pkg.CompNone, false); err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	if _, err := os.Stat(src + extension); err != nil {
		t.Errorf("sortie attendue %s: %v", src+extension, err)
	}
	if _, err := os.Stat(filepath.Join(src, extension)); err == nil {
		t.Error("un fichier caché a été créé dans le dossier chiffré")
	}
}

func TestDoEncryptRemplissage(t *testing.T) {
	dir := t.TempDir()
	in := ecrire(t, filepath.Join(dir, "doc.bin"), bytes.Repeat([]byte("a"), 5000))
	chto := filepath.Join(dir, "masque.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, chto, pkg.AlgoAES, pkg.CompNone, true); err != nil {
		t.Fatalf("chiffrement avec remplissage: %v", err)
	}
	d, err := pkg.Inspect(chto)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Padded {
		t.Error("le drapeau de remplissage n'est pas posé")
	}
	st, err := os.Stat(chto)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() <= 5000 {
		t.Errorf("le .chto fait %d octets pour 5000 octets de clair : rien n'a été ajouté", st.Size())
	}

	avecMotDePasse(t, motDePasseTest)
	out := filepath.Join(dir, "relu.bin")
	if err := doDecrypt(chto, out); err != nil {
		t.Fatalf("déchiffrement d'un fichier rempli: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5000 {
		t.Errorf("clair relu de %d octets, attendu 5000 : le remplissage n'a pas été retiré", len(got))
	}
}

// --- Flux standard ------------------------------------------------------

// TestDoEncryptVersSortieStandard couvre `-out -` : la sortie standard porte le
// .chto, et le résultat doit être relisible par le chemin normal.
func TestDoEncryptVersSortieStandard(t *testing.T) {
	dir := t.TempDir()
	contenu := []byte("données envoyées dans un tube\n")
	in := ecrire(t, filepath.Join(dir, "doc.txt"), contenu)

	sortie := captureSortie(t)
	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, "-", pkg.AlgoAES, pkg.CompNone, false); err != nil {
		t.Fatalf("chiffrement vers la sortie standard: %v", err)
	}

	// Le fichier de capture est renommé : doDecrypt exige l'extension, et c'est
	// bien ce qu'on veut vérifier — que les octets sortis du tube forment un
	// .chto valide, relisible par le chemin normal.
	brut, err := os.ReadFile(sortie)
	if err != nil {
		t.Fatal(err)
	}
	chto := ecrire(t, filepath.Join(dir, "depuis-tube.chto"), brut)

	out := filepath.Join(dir, "relu.txt")
	avecMotDePasse(t, motDePasseTest)
	if err := doDecrypt(chto, out); err != nil {
		t.Fatalf("relecture de ce qui est sorti du tube: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contenu, got) {
		t.Error("le contenu diffère après un passage par la sortie standard")
	}
}

// TestDoDecryptDossierVersSortieStandard couvre le `| tar xf -` annoncé dans
// l'aide : sur un tube, une archive sort en tar plutôt que d'être extraite.
func TestDoDecryptDossierVersSortieStandard(t *testing.T) {
	src := arbreCLI(t)
	chto := filepath.Join(t.TempDir(), "archive.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(src, chto, pkg.AlgoAES, pkg.CompNone, false); err != nil {
		t.Fatal(err)
	}

	sortie := captureSortie(t)
	avecMotDePasse(t, motDePasseTest)
	if err := doDecrypt(chto, "-"); err != nil {
		t.Fatalf("déchiffrement vers la sortie standard: %v", err)
	}

	f, err := os.Open(sortie)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	noms := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("ce qui est sorti n'est pas un tar lisible: %v", err)
		}
		noms[strings.TrimSuffix(hdr.Name, "/")] = true
	}
	for _, attendu := range []string{"a.txt", "sous", "sous/b.bin"} {
		if !noms[attendu] {
			t.Errorf("%s absent du tar produit (obtenu : %v)", attendu, noms)
		}
	}
}

func TestDoVerifyDepuisFlux(t *testing.T) {
	dir := t.TempDir()
	in := ecrire(t, filepath.Join(dir, "doc.txt"), []byte("à vérifier"))
	chto := filepath.Join(dir, "doc.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, chto, pkg.AlgoAES, pkg.CompZstd, false); err != nil {
		t.Fatal(err)
	}

	// Sur un flux, l'entrée standard porte les données : le mot de passe doit
	// venir du terminal, absent ici. L'outil doit refuser sans consommer les
	// données ni prétendre avoir vérifié quoi que ce soit.
	precedent := ttyDevice
	ttyDevice = filepath.Join(t.TempDir(), "pas-un-terminal")
	defer func() { ttyDevice = precedent }()

	avecEntree(t, chto)
	err := doVerify("-")
	if err == nil {
		t.Fatal("la vérification en flux a réussi sans mot de passe disponible")
	}
	if !strings.Contains(err.Error(), "-in FICHIER") {
		t.Errorf("l'erreur ne propose pas d'alternative : %v", err)
	}
}

// --- Refus --------------------------------------------------------------

func TestDoEncryptRefus(t *testing.T) {
	dir := t.TempDir()
	clair := ecrire(t, filepath.Join(dir, "doc.txt"), []byte("x"))
	dejaChiffre := ecrire(t, filepath.Join(dir, "doc.chto"), []byte("x"))

	cases := []struct {
		name    string
		in, out string
		comp    byte
		pad     bool
		motif   string
	}{
		{"entrée déjà chiffrée", dejaChiffre, "", pkg.CompNone, false, "déjà chiffré"},
		{"flux sans destination", "-", "", pkg.CompNone, false, "-out est obligatoire"},
		{"source égale destination", clair, clair, pkg.CompNone, false, "identiques"},
		{"remplissage et compression", clair, filepath.Join(dir, "x.chto"), pkg.CompZstd, true, "s'excluent"},
		{"entrée absente", filepath.Join(dir, "fantome.txt"), "", pkg.CompNone, false, "lecture"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			avecMotDePasse(t, motDePasseTest)
			err := doEncrypt(c.in, c.out, pkg.AlgoAES, c.comp, c.pad)
			if err == nil {
				t.Fatal("aucune erreur alors que le cas devrait être refusé")
			}
			if !strings.Contains(err.Error(), c.motif) {
				t.Errorf("erreur %q, attendu un message contenant %q", err, c.motif)
			}
		})
	}
}

func TestDoDecryptEtVerifyRefus(t *testing.T) {
	dir := t.TempDir()
	sansExtension := ecrire(t, filepath.Join(dir, "doc.txt"), []byte("x"))

	if err := doDecrypt(sansExtension, ""); err == nil {
		t.Error("un fichier sans extension .chto a été accepté au déchiffrement")
	}
	if err := doVerify(sansExtension); err == nil {
		t.Error("un fichier sans extension .chto a été accepté à la vérification")
	}
	if err := doDecrypt("-", ""); err == nil {
		t.Error("un flux sans -out a été accepté")
	}
	// Un .chto qui n'en est pas un : l'en-tête doit être refusé avant toute
	// demande de mot de passe, donc sans toucher à l'entrée standard.
	bidon := ecrire(t, filepath.Join(dir, "bidon.chto"), bytes.Repeat([]byte("X"), 64))
	if err := doDecrypt(bidon, filepath.Join(dir, "out")); err == nil {
		t.Error("un fichier au format inconnu a été accepté")
	}
	if err := doInfo("-"); err == nil {
		t.Error("info a accepté un flux, dont l'en-tête ne peut pas être relu")
	}
}

func TestDoDecryptMauvaisMotDePasse(t *testing.T) {
	dir := t.TempDir()
	in := ecrire(t, filepath.Join(dir, "doc.txt"), []byte("secret"))
	chto := filepath.Join(dir, "doc.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, chto, pkg.AlgoAES, pkg.CompNone, false); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "relu.txt")
	avecMotDePasse(t, "mauvais mot de passe")
	if err := doDecrypt(chto, out); err == nil {
		t.Fatal("un mauvais mot de passe a été accepté")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("un fichier de sortie a été laissé alors que le déchiffrement a échoué")
	}
}

// --- Vérification et inspection -----------------------------------------

func TestDoVerifyEtDoInfo(t *testing.T) {
	dir := t.TempDir()
	src := arbreCLI(t)
	chto := filepath.Join(dir, "archive.chto")

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(src, chto, pkg.AlgoCascade, pkg.CompGzip, false); err != nil {
		t.Fatal(err)
	}

	avecMotDePasse(t, motDePasseTest)
	if err := doVerify(chto); err != nil {
		t.Errorf("vérification d'une archive saine: %v", err)
	}

	avecMotDePasse(t, "mauvais")
	if err := doVerify(chto); err == nil {
		t.Error("la vérification a réussi avec un mauvais mot de passe")
	}

	sortie := captureSortie(t)
	if err := doInfo(chto); err != nil {
		t.Fatalf("inspection: %v", err)
	}
	brut, err := os.ReadFile(sortie)
	if err != nil {
		t.Fatal(err)
	}
	affiche := string(brut)
	for _, attendu := range []string{"format", "v3", "cascade", "gzip", "dossier", "remplissage", "argon2id"} {
		if !strings.Contains(affiche, attendu) {
			t.Errorf("la sortie de info ne mentionne pas %q :\n%s", attendu, affiche)
		}
	}
	// Les libellés ne doivent pas être coupés par la largeur de colonne.
	for _, ligne := range strings.Split(affiche, "\n") {
		if strings.HasSuffix(strings.TrimRight(ligne, " "), "compressio") {
			t.Error("un libellé est tronqué par la largeur de colonne")
		}
	}
}

// TestDoInfoAncienFormat : l'inspection d'un fichier v2 doit annoncer sa version
// et le signaler comme un format en lecture seule.
func TestDoInfoAncienFormat(t *testing.T) {
	ref := filepath.Join("pkg", "testdata", "v2_aes_gzip.chto")
	if _, err := os.Stat(ref); err != nil {
		t.Skipf("fichier de référence absent: %v", err)
	}

	sortie := captureSortie(t)
	if err := doInfo(ref); err != nil {
		t.Fatalf("inspection d'un fichier v2: %v", err)
	}
	brut, err := os.ReadFile(sortie)
	if err != nil {
		t.Fatal(err)
	}
	affiche := string(brut)
	for _, attendu := range []string{"v2", "gzip", "lecture seule"} {
		if !strings.Contains(affiche, attendu) {
			t.Errorf("la sortie ne mentionne pas %q :\n%s", attendu, affiche)
		}
	}
}

// --- Fonctions de décision ----------------------------------------------

func TestChooseComp(t *testing.T) {
	cases := []struct {
		compress bool
		algo     string
		want     byte
		wantErr  bool
	}{
		{false, "zstd", pkg.CompNone, false},
		{false, "n'importe quoi", pkg.CompNone, false}, // sans -comp, l'algo est sans effet
		{true, "zstd", pkg.CompZstd, false},
		{true, "gzip", pkg.CompGzip, false},
		{true, "bzip2", 0, true},
		{true, "", 0, true},
	}
	for _, c := range cases {
		got, err := chooseComp(c.compress, c.algo)
		if (err != nil) != c.wantErr {
			t.Errorf("chooseComp(%v, %q) erreur = %v, attendue: %v", c.compress, c.algo, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("chooseComp(%v, %q) = %d, attendu %d", c.compress, c.algo, got, c.want)
		}
	}
}

func TestDetailsSuffix(t *testing.T) {
	cases := []struct {
		name string
		d    pkg.Details
		want string
	}{
		{"rien", pkg.Details{}, ""},
		{"compressé", pkg.Details{Compressed: true, Comp: "zstd"}, " · zstd"},
		{"dossier", pkg.Details{Archive: true}, " · dossier"},
		{"rempli", pkg.Details{Padded: true}, " · taille masquée"},
		{"tout", pkg.Details{Compressed: true, Comp: "gzip", Archive: true, Padded: true},
			" · gzip · dossier · taille masquée"},
	}
	for _, c := range cases {
		if got := detailsSuffix(c.d); got != c.want {
			t.Errorf("%s : detailsSuffix = %q, attendu %q", c.name, got, c.want)
		}
	}
}

func TestIsStreamEtDescribeDest(t *testing.T) {
	if !isStream("-") {
		t.Error(`isStream("-") devrait être vrai`)
	}
	for _, p := range []string{"", "fichier", "./-", "-.txt", "a-"} {
		if isStream(p) {
			t.Errorf("isStream(%q) devrait être faux", p)
		}
	}
	if got := describeDest("-"); !strings.Contains(got, "sortie standard") {
		t.Errorf("describeDest(\"-\") = %q", got)
	}
	if got := describeDest("/tmp/a.chto"); got != "/tmp/a.chto" {
		t.Errorf("describeDest = %q, attendu le chemin tel quel", got)
	}
}

func TestOpenSourceEtOpenDest(t *testing.T) {
	dir := t.TempDir()
	chemin := ecrire(t, filepath.Join(dir, "f.bin"), bytes.Repeat([]byte("a"), 1234))

	r, size, closeSrc, err := openSource(chemin)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSrc()
	if size != 1234 {
		t.Errorf("taille annoncée %d, attendu 1234", size)
	}
	if n, _ := io.Copy(io.Discard, r); n != 1234 {
		t.Errorf("%d octets lus, attendu 1234", n)
	}

	// Sur un flux, la taille est inconnue : -1, pas 0 — un total de 0 voudrait
	// dire « vide » et afficherait une progression achevée d'emblée.
	_, size, closeStdin, err := openSource("-")
	if err != nil {
		t.Fatal(err)
	}
	closeStdin()
	if size != -1 {
		t.Errorf("taille d'un flux annoncée %d, attendu -1", size)
	}

	// La fermeture de la destination doit être idempotente : elle est appelée
	// explicitement pour remonter l'erreur, puis en defer.
	dest := filepath.Join(dir, "sortie")
	w, closeDst, err := openDest(dest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := closeDst(); err != nil {
		t.Fatalf("première fermeture: %v", err)
	}
	if err := closeDst(); err != nil {
		t.Errorf("seconde fermeture: %v (elle devrait être sans effet)", err)
	}
}

// --- Aide à la saisie ---------------------------------------------------

func TestCrackTime(t *testing.T) {
	// Les bits sont convertis en secondes par 2^bits / 10^4 essais : les
	// valeurs ci-dessous sont choisies au milieu de chaque palier, pas à ses
	// frontières, pour que le test décrive l'intention et non l'arrondi.
	cases := []struct {
		bits  float64
		motif string
	}{
		{0, "instantané"},
		{10, "secondes"}, // ~0,1 s
		{20, "minutes"},  // ~2 min
		{26, "heures"},   // ~2 h
		{31, "jours"},    // ~2,5 jours
		{36, "mois"},     // ~2,6 mois
		{42, "ans"},      // ~14 ans
		{200, "millénaires"},
	}
	for _, c := range cases {
		if got := crackTime(c.bits); !strings.Contains(got, c.motif) {
			t.Errorf("crackTime(%v) = %q, attendu un message contenant %q", c.bits, got, c.motif)
		}
	}

	// Et la progression doit être monotone : plus de bits ne doit jamais
	// donner un verdict plus court.
	rangs := map[string]int{
		"instantané": 0, "secondes": 1, "minutes": 2, "heures": 3,
		"jours": 4, "mois": 5, "ans": 6, "millénaires": 7,
	}
	rang := func(s string) int {
		for motif, r := range rangs {
			if strings.Contains(s, motif) {
				return r
			}
		}
		return -1
	}
	precedent := 0
	for bits := 0.0; bits < 120; bits += 0.5 {
		r := rang(crackTime(bits))
		if r < 0 {
			t.Fatalf("crackTime(%v) = %q, verdict non classable", bits, crackTime(bits))
		}
		if r < precedent {
			t.Errorf("crackTime recule à %v bits : %q après un palier plus long", bits, crackTime(bits))
		}
		precedent = r
	}
}

func TestCompressHint(t *testing.T) {
	if got := compressHint(true); !strings.Contains(got, "dossier") {
		t.Errorf("compressHint(dossier) = %q", got)
	}
	if got := compressHint(false); strings.Contains(got, "dossier") {
		t.Errorf("compressHint(fichier) parle de dossier : %q", got)
	}
}

func TestCibleTitreEtPlaceholder(t *testing.T) {
	if got := cibleTitre("enc"); !strings.Contains(got, "dossier") {
		t.Errorf("cibleTitre(enc) = %q, attendu qu'il mentionne le dossier", got)
	}
	for _, action := range []string{"dec", "verify"} {
		if got := cibleTitre(action); !strings.Contains(got, extension) {
			t.Errorf("cibleTitre(%s) = %q, attendu qu'il nomme l'extension", action, got)
		}
		if got := cibleTitre(action); strings.Contains(got, "dossier") {
			t.Errorf("cibleTitre(%s) = %q : un dossier n'est pas une cible ici", action, got)
		}
		if got := ciblePlaceholder(action); !strings.Contains(got, extension) {
			t.Errorf("ciblePlaceholder(%s) = %q", action, got)
		}
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("dossier personnel introuvable: %v", err)
	}
	if got := expandHome("~/docs/a.txt"); got != filepath.Join(home, "docs", "a.txt") {
		t.Errorf("expandHome = %q, attendu %q", got, filepath.Join(home, "docs", "a.txt"))
	}
	// Un tilde qui n'est pas un préfixe de chemin ne doit pas être touché.
	for _, p := range []string{"~", "a~/b", "~x/y", "/tmp/~/a"} {
		if got := expandHome(p); got != p {
			t.Errorf("expandHome(%q) = %q, attendu inchangé", p, got)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if err := validatePassword(""); err == nil {
		t.Error("un mot de passe vide devrait être refusé")
	}
	if err := validatePassword("a"); err != nil {
		t.Errorf("un mot de passe court est faible mais valide : %v", err)
	}
}

func TestZero(t *testing.T) {
	secret := []byte("mot de passe en mémoire")
	zero(secret)
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("octet %d non effacé : %q", i, b)
		}
	}
}

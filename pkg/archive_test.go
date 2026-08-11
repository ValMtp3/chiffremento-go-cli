package pkg

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// arbre construit un petit dossier de test et renvoie sa racine.
func arbre(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	dirs := []string{
		root,
		filepath.Join(root, "sous"),
		filepath.Join(root, "sous", "profond"),
		filepath.Join(root, "vide"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	files := []struct {
		path    string
		content []byte
	}{
		{filepath.Join(root, "a.txt"), []byte("premier fichier, accentué\n")},
		{filepath.Join(root, "sous", "b.bin"), bytes.Repeat([]byte{0x00, 0xff}, 5000)},
		{filepath.Join(root, "sous", "profond", "c.txt"), nil},
		{filepath.Join(root, "sous", "profond", "d é.txt"), []byte("nom avec espace et accent")},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// compareArbres vérifie que dst reproduit src : mêmes chemins relatifs, mêmes
// types, mêmes contenus.
func compareArbres(t *testing.T, src, dst string) {
	t.Helper()
	attendus := map[string]bool{} // chemin relatif -> est un dossier

	if err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil || rel == "." {
			return err
		}
		attendus[rel] = info.IsDir()
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for rel, estDossier := range attendus {
		cible := filepath.Join(dst, rel)
		info, err := os.Lstat(cible)
		if err != nil {
			t.Errorf("%s manque dans le dossier extrait: %v", rel, err)
			continue
		}
		if info.IsDir() != estDossier {
			t.Errorf("%s : type incorrect (dossier=%v, attendu %v)", rel, info.IsDir(), estDossier)
			continue
		}
		if estDossier {
			continue
		}
		got, err := os.ReadFile(cible)
		if err != nil {
			t.Errorf("lecture de %s: %v", rel, err)
			continue
		}
		want, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s : contenu différent après aller-retour", rel)
		}
	}

	// Et rien de plus que prévu : une extraction qui inventerait des fichiers
	// serait tout aussi grave qu'une extraction incomplète.
	if err := filepath.Walk(dst, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dst, p)
		if err != nil || rel == "." {
			return err
		}
		if _, ok := attendus[rel]; !ok {
			t.Errorf("%s est apparu dans le dossier extrait sans exister à la source", rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// --- Aller-retour sur un dossier ----------------------------------------

func TestRoundTripDossier(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"aes", Options{Algo: AlgoAES}},
		{"aes+gzip", Options{Algo: AlgoAES, Comp: CompGzip}},
		{"aes+zstd", Options{Algo: AlgoAES, Comp: CompZstd}},
		{"aes+remplissage", Options{Algo: AlgoAES, Pad: true}},
		{"cascade+zstd", Options{Algo: AlgoCascade, Comp: CompZstd}},
	}
	password := []byte("motdepassetest123")

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := arbre(t)
			work := t.TempDir()
			enc := filepath.Join(work, "archive.chto")
			dst := filepath.Join(work, "restaure")

			if err := Encrypt(src, enc, password, c.opts); err != nil {
				t.Fatalf("chiffrement du dossier: %v", err)
			}

			d, err := Inspect(enc)
			if err != nil {
				t.Fatal(err)
			}
			if !d.Archive {
				t.Error("le drapeau d'archive n'est pas posé dans l'en-tête")
			}
			if d.Compressed != (c.opts.Comp != CompNone) {
				t.Errorf("drapeau de compression = %v, attendu %v", d.Compressed, c.opts.Comp != CompNone)
			}
			if d.Padded != c.opts.Pad {
				t.Errorf("drapeau de remplissage = %v, attendu %v", d.Padded, c.opts.Pad)
			}

			if err := Verify(enc, password, Options{}); err != nil {
				t.Errorf("vérification d'une archive saine: %v", err)
			}
			if err := Decrypt(enc, dst, password, Options{}); err != nil {
				t.Fatalf("déchiffrement du dossier: %v", err)
			}
			compareArbres(t, src, dst)
		})
	}
}

func TestProgressionDossier(t *testing.T) {
	src := arbre(t)
	enc := filepath.Join(t.TempDir(), "archive.chto")

	attendu, err := InputSize(src)
	if err != nil {
		t.Fatal(err)
	}
	if attendu == 0 {
		t.Fatal("InputSize renvoie 0 pour un dossier non vide")
	}

	var dernier, total int64
	if err := Encrypt(src, enc, []byte("pw"), Options{
		Progress: func(done, tot int64) { dernier, total = done, tot },
	}); err != nil {
		t.Fatal(err)
	}
	if total != attendu {
		t.Errorf("total annoncé %d, attendu %d", total, attendu)
	}
	if dernier != attendu {
		t.Errorf("progression finale %d, attendu %d", dernier, attendu)
	}
}

// TestDossierDestinationExistante : un dossier déjà présent n'est jamais
// fusionné ni écrasé en silence.
func TestDossierDestinationExistante(t *testing.T) {
	src := arbre(t)
	work := t.TempDir()
	enc := filepath.Join(work, "archive.chto")
	dst := filepath.Join(work, "restaure")

	if err := Encrypt(src, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dst, "deja"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(enc, dst, []byte("pw"), Options{}); err == nil {
		t.Fatal("le déchiffrement a accepté une destination existante")
	}
	if _, err := os.Stat(filepath.Join(dst, "deja")); err != nil {
		t.Error("le contenu préexistant de la destination a été touché")
	}
}

// TestDossierMauvaisMotDePasse : rien ne doit rester sur le disque, ni dossier
// à moitié extrait, ni temporaire orphelin.
func TestDossierMauvaisMotDePasse(t *testing.T) {
	src := arbre(t)
	work := t.TempDir()
	enc := filepath.Join(work, "archive.chto")
	dst := filepath.Join(work, "restaure")

	if err := Encrypt(src, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(enc, dst, []byte("mauvais"), Options{}); err == nil {
		t.Fatal("un mot de passe faux a été accepté")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("un dossier a été créé malgré l'échec du déchiffrement")
	}

	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".chto-tmp-") {
			t.Errorf("temporaire orphelin laissé sur le disque: %s", e.Name())
		}
	}
}

func TestLienSymboliqueRefuse(t *testing.T) {
	src := arbre(t)
	if err := os.Symlink(filepath.Join(src, "a.txt"), filepath.Join(src, "lien")); err != nil {
		t.Skipf("liens symboliques indisponibles ici: %v", err)
	}
	enc := filepath.Join(t.TempDir(), "archive.chto")
	err := Encrypt(src, enc, []byte("pw"), Options{})
	if err == nil {
		t.Fatal("un dossier contenant un lien symbolique a été accepté")
	}
	if !strings.Contains(err.Error(), "lien") {
		t.Errorf("erreur peu explicite pour un lien symbolique: %v", err)
	}
	if _, err := os.Stat(enc); err == nil {
		t.Error("un fichier de sortie a été créé malgré le refus")
	}
}

// --- Archives hostiles --------------------------------------------------

// tarHostile fabrique un tar contenant les en-têtes donnés, sans passer par
// Encrypt : c'est le seul moyen de tester ce qu'une archive fabriquée à la main
// pourrait tenter à l'extraction.
func tarHostile(t *testing.T, headers []*tar.Header) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range headers {
		if h.Format == 0 {
			h.Format = tar.FormatPAX
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestExtractionRefuseLesCheminsHostiles(t *testing.T) {
	cases := []struct {
		name string
		hdr  *tar.Header
	}{
		{"remontée", &tar.Header{Name: "../evasion.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0644}},
		{"remontée cachée", &tar.Header{Name: "sous/../../evasion.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0644}},
		{"chemin absolu", &tar.Header{Name: "/etc/evasion", Typeflag: tar.TypeReg, Size: 1, Mode: 0644}},
		{"lien symbolique", &tar.Header{Name: "lien", Linkname: "../..", Typeflag: tar.TypeSymlink, Mode: 0777}},
		{"fifo", &tar.Header{Name: "tube", Typeflag: tar.TypeFifo, Mode: 0644}},
		{"trop profond", &tar.Header{
			Name: strings.Repeat("a/", maxRecursionDepth+2) + "f.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0644,
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := t.TempDir()
			r := tarHostile(t, []*tar.Header{c.hdr})
			if err := extractArchive(r, dst); err == nil {
				t.Fatal("archive hostile acceptée")
			}
			// Rien n'a pu sortir du dossier de destination : le parent du
			// TempDir ne doit contenir aucune trace.
			if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evasion.txt")); err == nil {
				t.Error("une entrée a été écrite hors du dossier de destination")
			}
		})
	}
}

func TestExtractionRefuseUnDoublon(t *testing.T) {
	dst := t.TempDir()
	r := tarHostile(t, []*tar.Header{
		{Name: "f.txt", Typeflag: tar.TypeReg, Size: 3, Mode: 0644},
		{Name: "f.txt", Typeflag: tar.TypeReg, Size: 3, Mode: 0644},
	})
	if err := extractArchive(r, dst); err == nil {
		t.Fatal("une archive décrivant deux fois le même chemin a été acceptée")
	}
}

func TestVerifyDetecteUneArchiveHostile(t *testing.T) {
	r := tarHostile(t, []*tar.Header{{Name: "../evasion.txt", Typeflag: tar.TypeReg, Size: 1, Mode: 0644}})
	if err := checkArchive(r); err == nil {
		t.Fatal("la vérification a validé une archive qu'on refuserait d'extraire")
	}
}

func TestSafeArchivePath(t *testing.T) {
	ok := []string{"a.txt", "sous/a.txt", "sous/./a.txt", "é/ b .txt"}
	for _, name := range ok {
		if _, err := safeArchivePath(name); err != nil {
			t.Errorf("safeArchivePath(%q) refusé à tort: %v", name, err)
		}
	}
	// "C:/x" n'est refusé que là où il est dangereux : sur Windows, où
	// filepath.VolumeName le reconnaît. Sur Unix c'est un nom de fichier
	// parfaitement banal, il n'y a rien à en craindre.
	ko := []string{"", ".", "..", "../x", "a/../../x", "/abs", "a\\b", "a\x00b"}
	for _, name := range ko {
		if _, err := safeArchivePath(name); err == nil {
			t.Errorf("safeArchivePath(%q) accepté à tort", name)
		}
	}
}

// TestArborescenceTropProfonde couvre le refus côté archivage, pendant du refus
// côté extraction : maxRecursionDepth s'applique dans les deux sens.
func TestArborescenceTropProfonde(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	profond := root
	for i := 0; i < maxRecursionDepth+2; i++ {
		profond = filepath.Join(profond, "a")
	}
	if err := os.MkdirAll(profond, 0755); err != nil {
		t.Skipf("impossible de créer une arborescence profonde ici: %v", err)
	}
	enc := filepath.Join(t.TempDir(), "archive.chto")
	if err := Encrypt(root, enc, []byte("pw"), Options{}); err == nil {
		t.Fatal("une arborescence trop profonde a été acceptée")
	}
}

// --- Fichier modifié en cours d'archivage -------------------------------

// infoTailleMenteuse annonce une taille différente de la réalité, ce qui simule
// un fichier modifié entre le scan et l'écriture de l'archive.
type infoTailleMenteuse struct {
	os.FileInfo
	taille int64
}

func (i infoTailleMenteuse) Size() int64 { return i.taille }

// TestFichierModifiePendantArchivage : la taille annoncée dans l'en-tête tar est
// lue au scan. Si le fichier change entre-temps, l'archive serait silencieusement
// incohérente — un tar que rien ne pourrait plus relire correctement. On préfère
// échouer.
func TestFichierModifiePendantArchivage(t *testing.T) {
	dir := t.TempDir()
	chemin := write(t, dir, "f.bin", bytes.Repeat([]byte("a"), 1000))
	reel, err := os.Stat(chemin)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		annonce int64
		motif   string
	}{
		{"le fichier a rétréci", 2000, "a changé de taille"},
		{"le fichier a grossi", 500, "a grossi"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := &archivePlan{
				entries: []archiveEntry{{
					abs:  chemin,
					rel:  "f.bin",
					info: infoTailleMenteuse{FileInfo: reel, taille: c.annonce},
				}},
				total: c.annonce,
			}
			err := writeArchive(io.Discard, plan, nil)
			if err == nil {
				t.Fatal("archive acceptée alors que la taille ne correspond pas")
			}
			if !strings.Contains(err.Error(), c.motif) {
				t.Errorf("erreur %q, attendu un message contenant %q", err, c.motif)
			}
		})
	}
}

// TestTarSizeExact couvre les cas où l'en-tête tar déborde du format historique
// et déclenche des enregistrements PAX supplémentaires : nom très long, nom non
// ASCII. C'est là que la taille calculée risquait de diverger du tar réel, et
// c'est le remplissage d'un dossier qui en dépend.
func TestTarSizeExact(t *testing.T) {
	root := filepath.Join(t.TempDir(), "source")
	profond := filepath.Join(root, strings.Repeat("dossier-au-nom-tres-long/", 4))
	if err := os.MkdirAll(profond, 0755); err != nil {
		t.Fatal(err)
	}
	write(t, profond, strings.Repeat("n", 120)+".txt", []byte("nom plus long que 100 caractères"))
	write(t, root, "accentué é à ü.txt", []byte("nom non ASCII"))
	write(t, root, "vide.txt", nil)
	write(t, root, "aligné-512.bin", bytes.Repeat([]byte("a"), 512))

	plan, err := scanDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	annonce, err := tarSize(plan)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := writeArchive(&buf, plan, nil); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) != annonce {
		t.Errorf("tarSize annonce %d octets, le tar produit en fait %d", annonce, buf.Len())
	}
}

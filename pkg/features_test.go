package pkg

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Profils KDF --------------------------------------------------------

func TestParseKDFProfile(t *testing.T) {
	for _, s := range []string{"", "standard", "fort", "maximum"} {
		if _, err := ParseKDFProfile(s); err != nil {
			t.Errorf("ParseKDFProfile(%q) refusé: %v", s, err)
		}
	}
	// « parano » est volontairement absent : le drapeau -parano désigne déjà le
	// double chiffrement, réutiliser le mot ici serait un piège.
	for _, s := range []string{"parano", "faible", "MAXIMUM", "3"} {
		if _, err := ParseKDFProfile(s); err == nil {
			t.Errorf("ParseKDFProfile(%q) accepté à tort", s)
		}
	}
	if p, _ := ParseKDFProfile(""); p != KDFStandard {
		t.Errorf("le profil vide devrait valoir standard, obtenu %q", p)
	}
}

// TestProfilsKDFCroissantsEtValides : chaque profil doit être plus coûteux que
// le précédent, et rester sous le plafond de lecture — sinon un fichier produit
// ici serait refusé par son propre déchiffrement.
func TestProfilsKDFCroissantsEtValides(t *testing.T) {
	var precedent argonParams
	for i, p := range AllKDFProfiles() {
		params := p.argonParams()
		if err := params.validate(); err != nil {
			t.Errorf("profil %q hors bornes: %v", p, err)
		}
		if params.Memory > maxArgonMemory {
			t.Errorf("profil %q : %d KiB dépasse le plafond de lecture %d",
				p, params.Memory, maxArgonMemory)
		}
		if i > 0 && params.Memory <= precedent.Memory && params.Time <= precedent.Time {
			t.Errorf("profil %q n'est pas plus coûteux que le précédent", p)
		}
		precedent = params
	}
}

// TestProfilKDFInscritDansLeHeader : le profil choisi doit se retrouver dans le
// fichier, sinon il serait impossible de le relire.
func TestProfilKDFInscritDansLeHeader(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("contenu"))
	enc := filepath.Join(dir, "fort.chto")

	if err := Encrypt(in, enc, []byte("pw"), Options{KDF: KDFFort}); err != nil {
		t.Fatal(err)
	}

	d, err := Inspect(enc)
	if err != nil {
		t.Fatal(err)
	}
	attendu := KDFFort.argonParams().String()
	if !strings.Contains(d.KDF, attendu) {
		t.Errorf("en-tête : %q, attendu contenant %q", d.KDF, attendu)
	}

	// Et le fichier doit se relire, ce qui prouve que la dérivation utilise bien
	// les paramètres lus et non ceux par défaut.
	dec := filepath.Join(dir, "sortie.txt")
	if err := Decrypt(enc, dec, []byte("pw"), Options{}); err != nil {
		t.Fatalf("relecture d'un fichier en profil fort: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != "contenu" {
		t.Errorf("contenu %q", got)
	}
}

func TestProfilKDFInconnuRefuse(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("x"))
	err := Encrypt(in, filepath.Join(dir, "o.chto"), []byte("pw"), Options{KDF: "parano"})
	if err == nil {
		t.Fatal("un profil inconnu a été accepté")
	}
	if _, err := os.Stat(filepath.Join(dir, "o.chto")); !os.IsNotExist(err) {
		t.Error("un fichier a été produit malgré le profil invalide")
	}
}

// --- Métadonnées --------------------------------------------------------

func TestParseMetadataMode(t *testing.T) {
	for _, s := range []string{"", "none", "minimal"} {
		if _, err := ParseMetadataMode(s); err != nil {
			t.Errorf("ParseMetadataMode(%q) refusé: %v", s, err)
		}
	}
	if _, err := ParseMetadataMode("complet"); err == nil {
		t.Error("un mode inconnu a été accepté")
	}
}

func TestMetadataAllerRetour(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "rapport-annuel.pdf", []byte("contenu confidentiel"))

	// Une date passée, pour vérifier qu'elle est bien restituée et non écrasée
	// par l'heure du déchiffrement.
	quand := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
	if err := os.Chtimes(in, quand, quand); err != nil {
		t.Fatal(err)
	}

	// Sortie au nom neutre : c'est tout l'intérêt de stocker le nom.
	enc := filepath.Join(dir, "a3f9c2.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{Metadata: MetadataMinimal}); err != nil {
		t.Fatal(err)
	}

	dec := filepath.Join(dir, "restitue.bin")
	res, err := DecryptTo(enc, dec, []byte("pw"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata == nil {
		t.Fatal("aucune métadonnée restituée")
	}
	if res.Metadata.Name != "rapport-annuel.pdf" {
		t.Errorf("nom restitué %q", res.Metadata.Name)
	}

	// La date est arrondie à l'heure : une date à la seconde corrélerait le
	// fichier avec des journaux système.
	if got := res.Metadata.ModTime; !got.Equal(quand.Truncate(time.Hour)) {
		t.Errorf("date restituée %v, attendu %v", got, quand.Truncate(time.Hour))
	}

	// Et elle doit être posée sur le fichier écrit.
	st, err := os.Stat(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().UTC().Equal(quand.Truncate(time.Hour)) {
		t.Errorf("date du fichier %v, attendu %v", st.ModTime().UTC(), quand.Truncate(time.Hour))
	}

	got, _ := os.ReadFile(dec)
	if string(got) != "contenu confidentiel" {
		t.Errorf("contenu %q", got)
	}
}

// TestSansMetadataParDefaut : ne rien écrire est le comportement par défaut,
// pour ne pas changer sous les pieds des utilisateurs existants.
func TestSansMetadataParDefaut(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("x"))
	enc := filepath.Join(dir, "o.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	res, err := DecryptTo(enc, filepath.Join(dir, "out.txt"), []byte("pw"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata != nil {
		t.Errorf("des métadonnées ont été écrites sans qu'on les demande: %+v", res.Metadata)
	}
}

// TestMetadataAvecRemplissage : la longueur du nom ne doit pas décaler la taille
// finale hors du palier, sinon elle se lirait sur la taille du fichier.
func TestMetadataAvecRemplissage(t *testing.T) {
	dir := t.TempDir()
	contenu := bytes.Repeat([]byte("a"), 5000)

	tailles := map[string]int64{}
	for _, nom := range []string{"a.txt", "un-nom-de-fichier-beaucoup-plus-long.txt"} {
		in := write(t, dir, nom, contenu)
		enc := filepath.Join(dir, nom+".chto")
		if err := Encrypt(in, enc, []byte("pw"), Options{Pad: true, Metadata: MetadataMinimal}); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(enc)
		if err != nil {
			t.Fatal(err)
		}
		tailles[nom] = st.Size()

		// Et le fichier doit rester lisible avec les deux options combinées.
		res, err := DecryptTo(enc, filepath.Join(dir, "out-"+nom), []byte("pw"), Options{})
		if err != nil {
			t.Fatalf("%s: %v", nom, err)
		}
		if res.Metadata == nil || res.Metadata.Name != nom {
			t.Errorf("%s: nom restitué %+v", nom, res.Metadata)
		}
	}

	var vues []int64
	for _, v := range tailles {
		vues = append(vues, v)
	}
	if vues[0] != vues[1] {
		t.Errorf("la longueur du nom fuit par la taille du fichier : %v", tailles)
	}
}

// TestMetadataNomHostile : le nom vient d'un fichier qu'on n'a pas produit. Même
// authentifié, il a été écrit par quelqu'un d'autre.
func TestMetadataNomHostile(t *testing.T) {
	// Sorties exactes, pas seulement « pas de séparateur » : c'est un test plus
	// strict, et le laxisme du précédent masquait un vrai bug sous Windows, où
	// « /etc/passwd » ressortait en « \\ ».
	//
	// Le résultat doit être identique sur tous les systèmes : le champ est
	// portable, il a pu être écrit ailleurs que là où il est relu.
	attendus := map[string]string{
		"../../.ssh/authorized_keys":      "authorized_keys",
		`..\..\Windows\System32\evil.dll`: "evil.dll",
		"/etc/passwd":                     "passwd",
		"./././x.txt":                     "x.txt",
		"dossier/sous/fichier.txt":        "fichier.txt",
		"rapport.pdf":                     "rapport.pdf",
	}
	for entree, attendu := range attendus {
		got, err := sanitizeMetaName(entree)
		if err != nil {
			t.Errorf("sanitizeMetaName(%q) refusé: %v", entree, err)
			continue
		}
		if got != attendu {
			t.Errorf("sanitizeMetaName(%q) = %q, attendu %q", entree, got, attendu)
		}
	}

	refuses := []string{
		"", ".", "..", "/", "/../", "../..", `\`, `\\`, "///",
		// Un « : » ouvrirait la porte aux chemins relatifs au lecteur sous
		// Windows, et un octet nul tronquerait le nom pour un appelant en C.
		"C:evil.txt", "flux:caché", "nom\x00tronqué",
	}
	for _, mauvais := range refuses {
		if got, err := sanitizeMetaName(mauvais); err == nil {
			t.Errorf("sanitizeMetaName(%q) accepté à tort, rendu %q", mauvais, got)
		}
	}
}

func TestMetadataBlocCorrompu(t *testing.T) {
	// Un bloc dont le magic ne correspond pas doit être refusé, pas interprété.
	if _, err := readMetadata(bytes.NewReader(bytes.Repeat([]byte("X"), 64))); err == nil {
		t.Error("un bloc de métadonnées invalide a été accepté")
	}
	// Tronqué avant la fin du préfixe.
	if _, err := readMetadata(bytes.NewReader([]byte("CHTMETA1"))); err == nil {
		t.Error("un bloc tronqué a été accepté")
	}
}

func TestMetadataNomTropLong(t *testing.T) {
	long := strings.Repeat("a", maxMetaName+1)
	if _, err := marshalMetadata(&FileMetadata{Name: long}); err == nil {
		t.Error("un nom au-delà du plafond a été accepté à l'écriture")
	}
}

// --- Benchmark ----------------------------------------------------------

func TestBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("mesure longue")
	}
	rep := Benchmark()

	if rep.CPUs < 1 {
		t.Error("nombre de cœurs invalide")
	}
	if len(rep.KDF) != len(AllKDFProfiles()) {
		t.Fatalf("%d profils mesurés, attendu %d", len(rep.KDF), len(AllKDFProfiles()))
	}
	for _, m := range rep.KDF {
		if m.Duration <= 0 {
			t.Errorf("profil %q : durée %v", m.Profile, m.Duration)
		}
		t.Logf("%-10s %-24s %5d Mio  %v", m.Profile, m.Label, m.MemoryMiB, m.Duration.Round(time.Millisecond))
	}

	// La recommandation doit être un profil réel, et jamais le plus lourd quand
	// aucun ne tient sous le plafond — c'était le bug de la première version.
	if _, err := ParseKDFProfile(string(rep.Advised)); err != nil {
		t.Errorf("profil conseillé invalide: %q", rep.Advised)
	}
	// Le profil conseillé ne doit jamais exiger plus que le plafond mémoire :
	// un fichier scellé avec lui doit rester déchiffrable sur une machine
	// ordinaire. Et il ne doit pas dépasser le plafond de durée, sauf si aucun
	// profil n'y tient — auquel cas le repli est le plus léger, pas le plus
	// lourd. C'était le bug de la première version.
	if rep.Advised.MemoryMiB() > benchAdviseMaxMemMiB {
		t.Errorf("profil conseillé %q exige %d Mio, au-delà du plafond de recommandation %d",
			rep.Advised, rep.Advised.MemoryMiB(), benchAdviseMaxMemMiB)
	}
	for _, m := range rep.KDF {
		if m.Profile != rep.Advised || m.Duration <= benchTargetMax {
			continue
		}
		for _, autre := range rep.KDF {
			if autre.Duration <= benchTargetMax && autre.MemoryMiB <= benchAdviseMaxMemMiB {
				t.Errorf("profil conseillé %q à %v alors que %q est éligible",
					rep.Advised, m.Duration, autre.Profile)
			}
		}
		if rep.Advised != KDFStandard {
			t.Errorf("aucun profil éligible : le repli doit être le plus léger, obtenu %q", rep.Advised)
		}
	}
	t.Logf("conseillé : %s", rep.Advisory)

	if len(rep.AEAD) != 3 {
		t.Fatalf("%d algorithmes mesurés, attendu 3", len(rep.AEAD))
	}
	for _, m := range rep.AEAD {
		if m.Err != nil {
			t.Errorf("%s: %v", m.Name, m.Err)
			continue
		}
		if m.BytesPerSec <= 0 {
			t.Errorf("%s: débit %d", m.Name, m.BytesPerSec)
		}
		t.Logf("%-34s %d Mio/s", m.Name, m.BytesPerSec>>20)
	}
}

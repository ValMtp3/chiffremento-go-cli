package pkg

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write crée un fichier de test et renvoie son chemin.
func write(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0644); err != nil {
		t.Fatalf("écriture de %s: %v", name, err)
	}
	return p
}

// --- Aller-retour -------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"aes", Options{Algo: AlgoAES}},
		{"aes+gzip", Options{Algo: AlgoAES, Compress: true}},
		{"chacha", Options{Algo: AlgoChaCha}},
		{"chacha+gzip", Options{Algo: AlgoChaCha, Compress: true}},
		{"cascade", Options{Algo: AlgoCascade}},
		{"cascade+gzip", Options{Algo: AlgoCascade, Compress: true}},
		{"algo par défaut", Options{}},
	}

	content := bytes.Repeat([]byte("Donnée répétitive, compressible et accentuée. "), 50)
	password := []byte("motdepassetest123")

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			in := write(t, dir, "clair.txt", content)
			enc := filepath.Join(dir, "chiffre.chto")
			dec := filepath.Join(dir, "dechiffre.txt")

			if err := Encrypt(in, enc, password, c.opts); err != nil {
				t.Fatalf("chiffrement: %v", err)
			}
			if err := Decrypt(enc, dec, password, Options{}); err != nil {
				t.Fatalf("déchiffrement: %v", err)
			}

			got, err := os.ReadFile(dec)
			if err != nil {
				t.Fatalf("lecture du déchiffré: %v", err)
			}
			if !bytes.Equal(content, got) {
				t.Error("le contenu déchiffré diffère de l'original")
			}
		})
	}
}

func TestRoundTripFichierVide(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "vide.txt", nil)
	enc := filepath.Join(dir, "vide.chto")
	dec := filepath.Join(dir, "vide.out")

	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	if err := Decrypt(enc, dec, []byte("pw"), Options{}); err != nil {
		t.Fatalf("déchiffrement: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if len(got) != 0 {
		t.Errorf("attendu un fichier vide, obtenu %d octets", len(got))
	}
}

func TestStreamingGrosFichier(t *testing.T) {
	if testing.Short() {
		t.Skip("test long")
	}
	dir := t.TempDir()
	content := make([]byte, 1024*1024)
	for i := range content {
		content[i] = byte(i % 251)
	}
	in := write(t, dir, "gros.bin", content)
	enc := filepath.Join(dir, "gros.chto")
	dec := filepath.Join(dir, "gros.out")

	if err := Encrypt(in, enc, []byte("streaming123"), Options{}); err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	if err := Decrypt(enc, dec, []byte("streaming123"), Options{}); err != nil {
		t.Fatalf("déchiffrement: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if !bytes.Equal(content, got) {
		t.Error("contenu différent après un aller-retour de 1 Mio")
	}
}

// --- Rejets -------------------------------------------------------------

func TestMauvaisMotDePasse(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "s.txt", []byte("secret"))
	enc := filepath.Join(dir, "s.chto")
	dec := filepath.Join(dir, "s.out")

	if err := Encrypt(in, enc, []byte("correct"), Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(enc, dec, []byte("incorrect"), Options{}); err == nil {
		t.Fatal("le déchiffrement aurait dû échouer")
	}
	if _, err := os.Stat(dec); !os.IsNotExist(err) {
		t.Error("un fichier de sortie a été laissé alors que le déchiffrement a échoué")
	}
}

func TestFichierInvalide(t *testing.T) {
	cases := map[string][]byte{
		"trop court":    []byte("court"),
		"magic inconnu": bytes.Repeat([]byte("X"), 64),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			in := write(t, dir, "bidon.chto", content)
			if err := Decrypt(in, filepath.Join(dir, "out"), []byte("pw"), Options{}); err == nil {
				t.Fatal("le déchiffrement aurait dû échouer")
			}
		})
	}
}

// TestHeaderFalsifie vérifie que chaque octet de l'en-tête est bien lié à la
// clé ou validé. Avant la v2, un algoID inconnu retombait silencieusement sur
// AES et l'octet de version n'était jamais relu.
func TestHeaderFalsifie(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("contenu confidentiel"))
	enc := filepath.Join(dir, "ref.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		offset int
		value  byte
	}{
		{"version inconnue", magicSize, 200},
		{"version v1 usurpée", magicSize, versionV1},
		{"drapeau inconnu", magicSize + 1, 0x80},
		{"drapeau compression retourné", magicSize + 1, FlagCompressed},
		{"algo inconnu", magicSize + 2, 99},
		{"algo substitué", magicSize + 2, AlgoChaCha},
		{"argon time falsifié", magicSize + 3, 9},
		{"argon memory falsifiée", magicSize + 7, 9},
		{"argon parallelism falsifié", magicSize + 11, 9},
		{"sel falsifié", magicSize + 12, 0xFF},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tampered := append([]byte(nil), ref...)
			if tampered[c.offset] == c.value {
				t.Skipf("l'octet %d vaut déjà %d", c.offset, c.value)
			}
			tampered[c.offset] = c.value

			path := write(t, t.TempDir(), "falsifie.chto", tampered)
			out := filepath.Join(filepath.Dir(path), "out")
			if err := Decrypt(path, out, []byte("pw"), Options{}); err == nil {
				t.Fatal("un en-tête falsifié a été accepté")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Error("un fichier de sortie a été produit malgré l'échec")
			}
		})
	}
}

func TestParametresArgonHorsBornes(t *testing.T) {
	cases := []argonParams{
		{Time: 0, Memory: defaultArgonMemory, Threads: 4},
		{Time: maxArgonTime + 1, Memory: defaultArgonMemory, Threads: 4},
		{Time: 3, Memory: 0, Threads: 4},
		{Time: 3, Memory: maxArgonMemory + 1, Threads: 4}, // ~ 2 GiB : ferait exploser la RAM
		{Time: 3, Memory: defaultArgonMemory, Threads: 0},
		{Time: 3, Memory: defaultArgonMemory, Threads: maxArgonThreads + 1},
	}
	for _, p := range cases {
		if err := p.validate(); err == nil {
			t.Errorf("paramètres acceptés à tort: %+v", p)
		}
	}
	if err := defaultArgonParams().validate(); err != nil {
		t.Errorf("les paramètres par défaut devraient être valides: %v", err)
	}
	if err := legacyArgonParams().validate(); err != nil {
		t.Errorf("les paramètres v1 devraient rester valides: %v", err)
	}
}

// TestHeaderMemoireHostile passe par le vrai chemin de lecture : un .chto qui
// annonce 4 TiB de mémoire Argon2 doit être refusé avant toute allocation.
func TestHeaderMemoireHostile(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("x"))
	enc := filepath.Join(dir, "ref.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(enc)

	// argonMemory est un uint32 big-endian placé juste après argonTime.
	off := magicSize + versionSize + flagsSize + algoIDSize + 4
	raw[off], raw[off+1], raw[off+2], raw[off+3] = 0xFF, 0xFF, 0xFF, 0xFF

	path := write(t, dir, "hostile.chto", raw)
	err := Decrypt(path, filepath.Join(dir, "out"), []byte("pw"), Options{})
	if err == nil {
		t.Fatal("un header annonçant 4 TiB de mémoire a été accepté")
	}
	if !strings.Contains(err.Error(), "hors bornes") {
		t.Errorf("erreur inattendue: %v", err)
	}
}

// --- Perte de données ---------------------------------------------------

// TestEchecNeDetruitPasLaCible rejoue le scénario le plus destructeur de la
// v1 : os.Create tronquait la destination avant toute vérification, donc
// déchiffrer un .chto corrompu vers un fichier existant le détruisait.
func TestEchecNeDetruitPasLaCible(t *testing.T) {
	dir := t.TempDir()
	precieux := write(t, dir, "important.txt", []byte("MES DONNÉES PRÉCIEUSES"))
	write(t, dir, "important.txt.chto", []byte("ceci n'est pas un fichier chiffré"))

	if err := Decrypt(filepath.Join(dir, "important.txt.chto"), precieux, []byte("pw"), Options{}); err == nil {
		t.Fatal("le déchiffrement aurait dû échouer")
	}

	got, err := os.ReadFile(precieux)
	if err != nil {
		t.Fatalf("le fichier original a disparu: %v", err)
	}
	if string(got) != "MES DONNÉES PRÉCIEUSES" {
		t.Errorf("le fichier original a été altéré: %q", got)
	}
	assertPasDeTemporaire(t, dir)
}

// TestTronquageNeLaissePasDeClair : un ciphertext amputé produit du clair
// authentifié jusqu'au point de coupure. Ce clair ne doit jamais atteindre le
// chemin final.
func TestTronquageNeLaissePasDeClair(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 300*1024)
	for i := range content {
		content[i] = byte(i)
	}
	in := write(t, dir, "gros.bin", content)
	enc := filepath.Join(dir, "gros.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(enc)
	tronque := write(t, dir, "tronque.chto", raw[:len(raw)-100])

	out := filepath.Join(dir, "sortie.bin")
	if err := Decrypt(tronque, out, []byte("pw"), Options{}); err == nil {
		t.Fatal("un ciphertext tronqué a été accepté")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("du clair non authentifié a été laissé sur le chemin final")
	}
	assertPasDeTemporaire(t, dir)
}

func assertPasDeTemporaire(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".chto-tmp-") {
			t.Errorf("fichier temporaire abandonné: %s", e.Name())
		}
	}
}

func TestPermissions(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "s.txt", []byte("secret"))
	enc := filepath.Join(dir, "s.chto")
	dec := filepath.Join(dir, "s.out")

	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(enc, dec, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{enc, dec} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Errorf("%s : permissions %v (attendu 0600)", filepath.Base(p), mode)
		}
	}
}

// --- Progression --------------------------------------------------------

func TestProgression(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 200*1024)
	in := write(t, dir, "gros.bin", content)

	var appels int
	var dernier, total int64
	opts := Options{Progress: func(done, tot int64) {
		appels++
		if done < dernier {
			t.Errorf("progression en recul : %d après %d", done, dernier)
		}
		dernier, total = done, tot
	}}

	if err := Encrypt(in, filepath.Join(dir, "o.chto"), []byte("pw"), opts); err != nil {
		t.Fatal(err)
	}
	if appels == 0 {
		t.Fatal("le callback de progression n'a jamais été appelé")
	}
	if total != int64(len(content)) {
		t.Errorf("total annoncé %d, attendu %d", total, len(content))
	}
	if dernier != int64(len(content)) {
		t.Errorf("progression finale %d, attendu %d", dernier, len(content))
	}
}

// --- Dérivation de clé --------------------------------------------------

func TestDeriveKey(t *testing.T) {
	password := []byte("monSecret")
	salt := make([]byte, saltSize)
	p := legacyArgonParams() // le moins cher, suffisant pour ce test

	key1, err := deriveKey(password, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := deriveKey(password, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("deriveKey n'est pas déterministe")
	}

	autreSel := make([]byte, saltSize)
	autreSel[0] = 1
	key3, err := deriveKey(password, autreSel, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("deriveKey ignore le sel")
	}

	// Un sel de mauvaise taille doit être refusé, pas silencieusement remplacé
	// par un sel aléatoire non renvoyé — ce que faisait la v1.
	if _, err := deriveKey(password, nil, p); err == nil {
		t.Error("un sel vide a été accepté")
	}
	if _, err := deriveKey(password, make([]byte, 8), p); err == nil {
		t.Error("un sel de 8 octets a été accepté")
	}
}

// TestCascadeUneSeuleDerivation : en v2, le mode cascade ne doit coûter qu'un
// seul Argon2. La v1 en faisait deux côté défenseur alors que l'attaquant n'en
// avait besoin que d'un seul, ce qui rendait le mode « parano » plus faible
// que le mode standard à temps CPU égal.
func TestCascadeUneSeuleDerivation(t *testing.T) {
	h := &header{
		Version: versionV2,
		Algo:    AlgoCascade,
		Argon:   legacyArgonParams(),
		Salt:    make([]byte, saltSize),
	}
	h.marshal()

	keys, err := deriveKeysV2([]byte("pw"), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Inner) != 32 || len(keys.Outer) != 32 {
		t.Fatalf("sous-clés de tailles inattendues: %d / %d", len(keys.Inner), len(keys.Outer))
	}
	if bytes.Equal(keys.Inner, keys.Outer) {
		t.Fatal("les deux couches partagent la même clé")
	}

	// L'en-tête entre dans l'info HKDF : un octet modifié doit tout changer.
	h2 := &header{Version: versionV2, Algo: AlgoCascade, Argon: legacyArgonParams(), Salt: make([]byte, saltSize)}
	h2.Flags = FlagCompressed
	h2.marshal()
	keys2, err := deriveKeysV2([]byte("pw"), h2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.Inner, keys2.Inner) {
		t.Fatal("un changement de drapeau dans l'en-tête ne change pas la clé")
	}
}

// --- Compatibilité v1 ---------------------------------------------------

// TestCompatibiliteV1 déchiffre des fichiers produits par la v1.1.0 elle-même
// (générés avec l'ancien code, pas réimplémentés). C'est le seul garde-fou
// qui empêche de casser silencieusement les .chto déjà chez les utilisateurs.
func TestCompatibiliteV1(t *testing.T) {
	const password = "reference-v1-password"
	cases := map[string]string{
		"v1_aes.chto":      "Fichier de reference v1 chiffre en AES-256-GCM.\n",
		"v1_chacha.chto":   "Fichier de reference v1 chiffre en ChaCha20-Poly1305.\n",
		"v1_cascade.chto":  "Fichier de reference v1 chiffre en mode cascade (parano).\n",
		"v1_aes_gzip.chto": "Fichier de reference v1 compresse puis chiffre en AES-256-GCM.\n",
	}

	for name, attendu := range cases {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("testdata", name)
			version, algo, kdf, _, err := Inspect(src)
			if err != nil {
				t.Fatalf("inspection: %v", err)
			}
			if version != versionV1 {
				t.Fatalf("version %d, attendu %d", version, versionV1)
			}
			t.Logf("%s : %s, %s", name, algo, kdf)

			out := filepath.Join(t.TempDir(), "out.txt")
			if err := Decrypt(src, out, []byte(password), Options{}); err != nil {
				t.Fatalf("déchiffrement d'un fichier v1: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != attendu {
				t.Errorf("contenu inattendu:\nobtenu : %q\nattendu: %q", got, attendu)
			}
		})
	}
}

func TestEncryptEcritToujoursDuV2(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("x"))
	enc := filepath.Join(dir, "out.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	version, _, kdf, _, err := Inspect(enc)
	if err != nil {
		t.Fatal(err)
	}
	if version != versionV2 {
		t.Errorf("version écrite %d, attendu %d", version, versionV2)
	}
	if !strings.Contains(kdf, "m=256MiB") {
		t.Errorf("paramètres Argon2 inattendus dans le header: %s", kdf)
	}
}

// --- Tripwire de format -------------------------------------------------

// TestProtocolSafety_Tripwire fige la structure binaire. Si tu modifies le
// format dans format.go, tu DOIS mettre ce test à jour ET te demander si ça
// mérite un bump de version.
func TestProtocolSafety_Tripwire(t *testing.T) {
	const (
		expectedVersion    = 2
		expectedHeaderV1   = 27 // 8+1+1+1+16
		expectedHeaderV2   = 36 // 8+1+1+1+4+4+1+16
		expectedMagic      = "CHFRMT03"
		expectedKnownFlags = FlagCompressed
	)

	if currentVersion < expectedVersion {
		t.Fatalf("CRITIQUE : la version du protocole a reculé (code: %d, attendu >= %d)", currentVersion, expectedVersion)
	}

	structureChanged := false
	if headerSizeV1 != expectedHeaderV1 {
		t.Logf("⚠️  la taille du header v1 a changé (avant: %d, maintenant: %d)", expectedHeaderV1, headerSizeV1)
		structureChanged = true
	}
	if headerSizeV2 != expectedHeaderV2 {
		t.Logf("⚠️  la taille du header v2 a changé (avant: %d, maintenant: %d)", expectedHeaderV2, headerSizeV2)
		structureChanged = true
	}
	if magicNumber != expectedMagic {
		t.Logf("⚠️  le magic number a changé (avant: %s, maintenant: %s)", expectedMagic, magicNumber)
		structureChanged = true
	}
	if knownFlags != expectedKnownFlags {
		t.Logf("⚠️  la liste des drapeaux connus a changé (avant: %d, maintenant: %d)", expectedKnownFlags, knownFlags)
		structureChanged = true
	}

	if structureChanged && currentVersion == expectedVersion {
		t.Fatalf("🛑 STOP ! Tu as modifié la structure du fichier mais oublié d'incrémenter 'currentVersion' dans format.go.\n"+
			"-> Si le changement est rétrocompatible, mets ce test à jour.\n"+
			"-> Sinon, passe currentVersion à %d et ajoute un chemin de lecture pour l'ancienne version.", expectedVersion+1)
	}

	// La lecture des anciens fichiers doit rester possible tant que des .chto
	// v1 existent dans la nature.
	if versionV1 != 1 {
		t.Error("l'identifiant de la version 1 ne doit pas changer")
	}
	if _, err := os.Stat(filepath.Join("testdata", "v1_aes.chto")); err != nil {
		t.Error("les fichiers v1 de référence ont disparu de testdata/ : la compatibilité n'est plus testée")
	}
}

// --- Vérification sans écriture -----------------------------------------

func TestVerify(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("données à contrôler. "), 200)
	in := write(t, dir, "clair.txt", content)
	enc := filepath.Join(dir, "clair.txt.chto")

	if err := Encrypt(in, enc, []byte("pw"), Options{Compress: true}); err != nil {
		t.Fatal(err)
	}

	if err := Verify(enc, []byte("pw"), Options{}); err != nil {
		t.Fatalf("un fichier intact a été rejeté: %v", err)
	}

	// Verify ne doit produire aucun fichier : le répertoire contenait le clair
	// et le chiffré, il ne doit rien contenir de plus.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		var noms []string
		for _, e := range entries {
			noms = append(noms, e.Name())
		}
		t.Errorf("Verify a laissé des fichiers derrière lui: %v", noms)
	}

	if err := Verify(enc, []byte("mauvais"), Options{}); err == nil {
		t.Error("un mauvais mot de passe a été accepté")
	}

	// Un octet retourné au milieu du corps chiffré doit être détecté.
	raw, _ := os.ReadFile(enc)
	raw[len(raw)/2] ^= 0xFF
	corrompu := write(t, dir, "corrompu.chto", raw)
	if err := Verify(corrompu, []byte("pw"), Options{}); err == nil {
		t.Error("un fichier corrompu a été déclaré intact")
	}
}

func TestVerifyFichierV1(t *testing.T) {
	if err := Verify(filepath.Join("testdata", "v1_cascade.chto"), []byte("reference-v1-password"), Options{}); err != nil {
		t.Errorf("un fichier v1 intact a été rejeté: %v", err)
	}
}

// TestNettoyageTemporaires vérifie le filet de sécurité appelé par le
// gestionnaire de signal : un Ctrl+C ne doit pas laisser de .chto-tmp-*.
func TestNettoyageTemporaires(t *testing.T) {
	dir := t.TempDir()
	a, err := newAtomicFile(filepath.Join(dir, "cible"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := a.f.Name()
	if _, err := os.Stat(tmp); err != nil {
		t.Fatalf("le temporaire devrait exister: %v", err)
	}

	CleanupTemporaries()

	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("CleanupTemporaries n'a pas supprimé le temporaire en cours")
	}
	a.cleanup()
}

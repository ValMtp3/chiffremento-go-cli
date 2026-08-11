package pkg

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Compatibilité v2 ---------------------------------------------------

// TestCompatibiliteV2 déchiffre des fichiers produits par le format v2, avant
// l'arrivée du champ compAlgo. C'est le garde-fou qui empêche de casser les
// .chto déjà chez les utilisateurs — y compris ceux qui contiennent un dossier,
// puisque les archives existaient déjà en v2.
func TestCompatibiliteV2(t *testing.T) {
	const password = "reference-v2-password"
	cases := map[string]string{
		"v2_aes.chto":      "Fichier de reference v2 chiffre en AES-256-GCM.\n",
		"v2_chacha.chto":   "Fichier de reference v2 chiffre en ChaCha20-Poly1305.\n",
		"v2_cascade.chto":  "Fichier de reference v2 chiffre en mode cascade (parano).\n",
		"v2_aes_gzip.chto": "Fichier de reference v2 compresse puis chiffre en AES-256-GCM.\n",
	}

	for name, attendu := range cases {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("testdata", name)
			d, err := Inspect(src)
			if err != nil {
				t.Fatalf("inspection: %v", err)
			}
			if d.Version != versionV2 {
				t.Fatalf("version %d, attendu %d", d.Version, versionV2)
			}
			// En v2, le drapeau de compression signifiait gzip : c'est ce que la
			// lecture doit en déduire, sans champ compAlgo dans le fichier.
			wantComp := "aucune"
			if strings.Contains(name, "gzip") {
				wantComp = "gzip"
			}
			if d.Comp != wantComp {
				t.Errorf("compression lue %q, attendu %q", d.Comp, wantComp)
			}

			out := filepath.Join(t.TempDir(), "out.txt")
			if err := Decrypt(src, out, []byte(password), Options{}); err != nil {
				t.Fatalf("déchiffrement d'un fichier v2: %v", err)
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

func TestCompatibiliteV2Dossier(t *testing.T) {
	const password = "reference-v2-password"
	src := filepath.Join("testdata", "v2_dossier_gzip.chto")

	d, err := Inspect(src)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != versionV2 || !d.Archive || d.Comp != "gzip" {
		t.Fatalf("en-tête inattendu : v%d archive=%v comp=%s", d.Version, d.Archive, d.Comp)
	}

	dst := filepath.Join(t.TempDir(), "restaure")
	if err := Decrypt(src, dst, []byte(password), Options{}); err != nil {
		t.Fatalf("déchiffrement d'une archive v2: %v", err)
	}
	for rel, attendu := range map[string]string{
		"a.txt":      "premier\n",
		"sous/b.txt": "second\n",
	} {
		got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("lecture de %s: %v", rel, err)
			continue
		}
		if string(got) != attendu {
			t.Errorf("%s : contenu %q, attendu %q", rel, got, attendu)
		}
	}
}

func TestEncryptEcritDuV3(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("x"))
	enc := filepath.Join(dir, "out.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{Comp: CompZstd}); err != nil {
		t.Fatal(err)
	}
	d, err := Inspect(enc)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != versionV3 {
		t.Errorf("version écrite %d, attendu %d", d.Version, versionV3)
	}
	if d.Comp != "zstd" {
		t.Errorf("compression annoncée %q, attendu zstd", d.Comp)
	}

	// Le drapeau de compression v1/v2 ne doit plus être écrit : compAlgo fait foi.
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	if raw[magicSize+versionSize]&FlagCompressed != 0 {
		t.Error("le drapeau de compression v1/v2 est encore posé sur un fichier v3")
	}
}

// TestHeaderIncoherentRefuse : les deux façons de décrire la compression ne
// doivent jamais coexister, et le remplissage n'existe pas avant la v3.
func TestHeaderIncoherentRefuse(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("x"))
	enc := filepath.Join(dir, "ref.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}

	// v3 + drapeau de compression v1/v2.
	tampered := append([]byte(nil), raw...)
	tampered[magicSize+versionSize] |= FlagCompressed
	if _, err := readHeader(bytes.NewReader(tampered)); err == nil {
		t.Error("un header v3 portant le drapeau de compression v1/v2 a été accepté")
	}

	// v2 + drapeau de remplissage.
	v2 := append([]byte(nil), raw...)
	v2[magicSize] = versionV2
	v2[magicSize+versionSize] |= FlagPadded
	if _, err := readHeader(bytes.NewReader(v2)); err == nil {
		t.Error("un header v2 portant le drapeau de remplissage a été accepté")
	}
}

// --- Remplissage --------------------------------------------------------

func TestPadme(t *testing.T) {
	// Les paliers sont monotones, jamais inférieurs à la taille demandée, et le
	// surcoût reste sous les ~12 % annoncés par le schéma.
	var precedent int64
	for _, taille := range []int64{1, 2, 7, 8, 100, 1000, 1024, 5000, 1 << 20, (1 << 20) + 1, 1 << 30} {
		got := padme(taille)
		if got < taille {
			t.Errorf("padme(%d) = %d, inférieur à la taille demandée", taille, got)
		}
		if got < precedent {
			t.Errorf("padme n'est pas monotone : padme(%d) = %d après %d", taille, got, precedent)
		}
		precedent = got
		if surcout := float64(got-taille) / float64(taille); surcout > 0.13 {
			t.Errorf("padme(%d) = %d, surcoût de %.1f %% (attendu ≤ 12 %%)", taille, got, surcout*100)
		}
	}
	if padme(0) != 0 {
		t.Error("padme(0) devrait valoir 0")
	}

	// La propriété qui masque vraiment quelque chose n'est pas « deux tailles
	// voisines se confondent » — un arrondi laisse toujours passer une frontière
	// entre deux valeurs proches — mais « il existe peu de tailles possibles ».
	// Sur toute une octave, entre 64 Kio et 128 Kio, il ne doit rester qu'une
	// poignée de paliers, soit un fichier noyé parmi des milliers d'autres.
	paliers := map[int64]struct{}{}
	for taille := int64(65536); taille < 131072; taille += 37 {
		paliers[padme(taille)] = struct{}{}
	}
	if len(paliers) > 40 {
		t.Errorf("%d paliers distincts entre 64 et 128 Kio : le remplissage ne masque presque rien", len(paliers))
	}
	if len(paliers) < 2 {
		t.Error("un seul palier sur une octave entière : le surcoût serait énorme")
	}
}

// TestRemplissageMasqueLaTaille est le test qui donne son sens à l'option : deux
// fichiers de tailles différentes mais proches doivent produire des .chto de
// taille identique.
func TestRemplissageMasqueLaTaille(t *testing.T) {
	dir := t.TempDir()
	password := []byte("pw")

	tailleChto := func(clair int) int64 {
		t.Helper()
		sous := t.TempDir()
		in := write(t, sous, "clair.bin", bytes.Repeat([]byte("a"), clair))
		enc := filepath.Join(sous, "out.chto")
		if err := Encrypt(in, enc, password, Options{Pad: true}); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(enc)
		if err != nil {
			t.Fatal(err)
		}
		return st.Size()
	}

	// 98 400 et 100 000 octets tombent dans le même palier Padmé : à cette
	// échelle, le palier fait 2 Kio, donc deux tailles séparées de moins de
	// ~2 % se confondent.
	if got, want := padme(98400+padHeaderSize), padme(100000+padHeaderSize); got != want {
		t.Fatalf("prémisse du test fausse : paliers %d et %d, attendus égaux", got, want)
	}
	a, b := tailleChto(98400), tailleChto(100000)
	if a != b {
		t.Errorf("deux tailles du même palier produisent des .chto de %d et %d octets : la taille n'est pas masquée", a, b)
	}

	// Sans remplissage, elles se distinguent — sinon le test ci-dessus ne
	// prouverait rien.
	in1 := write(t, dir, "un.bin", bytes.Repeat([]byte("a"), 98400))
	in2 := write(t, dir, "deux.bin", bytes.Repeat([]byte("a"), 100000))
	e1, e2 := filepath.Join(dir, "un.chto"), filepath.Join(dir, "deux.chto")
	if err := Encrypt(in1, e1, password, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(in2, e2, password, Options{}); err != nil {
		t.Fatal(err)
	}
	s1, _ := os.Stat(e1)
	s2, _ := os.Stat(e2)
	if s1.Size() == s2.Size() {
		t.Error("sans remplissage, deux tailles différentes donnent le même .chto : le test ne prouve rien")
	}
}

// TestRemplissageDossierViseLePalier vérifie que tarSize est exact : sinon le
// remplissage d'un dossier viserait à côté du palier.
func TestRemplissageDossierViseLePalier(t *testing.T) {
	src := arbre(t)
	plan, err := scanDirectory(src)
	if err != nil {
		t.Fatal(err)
	}
	attendu, err := tarSize(plan)
	if err != nil {
		t.Fatal(err)
	}

	// La taille annoncée doit être exactement celle du tar réellement produit.
	var buf bytes.Buffer
	if err := writeArchive(&buf, plan, nil); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) != attendu {
		t.Fatalf("tarSize annonce %d octets, le tar produit en fait %d", attendu, buf.Len())
	}

	// Et le clair chiffré avec remplissage atteint bien le palier.
	enc := filepath.Join(t.TempDir(), "archive.chto")
	if err := Encrypt(src, enc, []byte("pw"), Options{Pad: true}); err != nil {
		t.Fatal(err)
	}
	payload := attendu + padHeaderSize + paddingFor(attendu)
	if payload != padme(attendu+padHeaderSize) {
		t.Errorf("charge utile de %d octets, palier attendu %d", payload, padme(attendu+padHeaderSize))
	}
}

func TestRemplissageEtCompressionSExcluent(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", []byte("contenu"))
	enc := filepath.Join(dir, "out.chto")

	err := Encrypt(in, enc, []byte("pw"), Options{Pad: true, Comp: CompZstd})
	if err == nil {
		t.Fatal("remplissage et compression combinés ont été acceptés")
	}
	if !strings.Contains(err.Error(), "s'excluent") {
		t.Errorf("erreur peu explicite : %v", err)
	}
	if _, err := os.Stat(enc); err == nil {
		t.Error("un fichier a été créé malgré le refus")
	}
}

// TestRemplissageHostile : un fichier qui annonce plus de remplissage qu'il n'en
// contient doit échouer proprement, pas boucler ni rendre du clair tronqué.
func TestRemplissageHostile(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", bytes.Repeat([]byte("x"), 1000))
	enc := filepath.Join(dir, "ref.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{Pad: true}); err != nil {
		t.Fatal(err)
	}

	// Le drapeau est authentifié : le retirer doit faire échouer la dérivation,
	// donc le déchiffrement, sans jamais livrer le remplissage comme du clair.
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	raw[magicSize+versionSize] &^= FlagPadded
	path := write(t, dir, "sans_drapeau.chto", raw)
	if err := Decrypt(path, filepath.Join(dir, "out"), []byte("pw"), Options{}); err == nil {
		t.Error("retirer le drapeau de remplissage n'a pas fait échouer le déchiffrement")
	}
}

// --- Flux standard ------------------------------------------------------

func TestFluxAllerRetour(t *testing.T) {
	content := bytes.Repeat([]byte("données de flux, accentuées. "), 500)
	password := []byte("pw")

	for _, c := range []struct {
		name string
		opts Options
	}{
		{"sans compression", Options{}},
		{"zstd", Options{Comp: CompZstd}},
		{"gzip", Options{Comp: CompGzip}},
		{"cascade+zstd", Options{Algo: AlgoCascade, Comp: CompZstd}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var chiffre bytes.Buffer
			// -1 : taille inconnue, comme sur l'entrée standard.
			if err := EncryptStream(&chiffre, bytes.NewReader(content), -1, password, c.opts); err != nil {
				t.Fatalf("chiffrement en flux: %v", err)
			}

			var clair bytes.Buffer
			if err := DecryptStream(&clair, bytes.NewReader(chiffre.Bytes()), password, Options{}); err != nil {
				t.Fatalf("déchiffrement en flux: %v", err)
			}
			if !bytes.Equal(content, clair.Bytes()) {
				t.Error("le contenu diffère après un aller-retour en flux")
			}

			if err := VerifyStream(bytes.NewReader(chiffre.Bytes()), password, Options{}); err != nil {
				t.Errorf("vérification en flux: %v", err)
			}
		})
	}
}

// TestFluxInteroperable : un fichier écrit sur disque se relit en flux, et
// inversement. Les deux chemins doivent produire exactement le même format.
func TestFluxInteroperable(t *testing.T) {
	dir := t.TempDir()
	content := []byte("interopérabilité disque / flux")
	in := write(t, dir, "clair.txt", content)
	enc := filepath.Join(dir, "sur_disque.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{Comp: CompZstd}); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var clair bytes.Buffer
	if err := DecryptStream(&clair, f, []byte("pw"), Options{}); err != nil {
		t.Fatalf("lecture en flux d'un fichier écrit sur disque: %v", err)
	}
	if !bytes.Equal(content, clair.Bytes()) {
		t.Error("contenu différent")
	}

	var chiffre bytes.Buffer
	if err := EncryptStream(&chiffre, bytes.NewReader(content), int64(len(content)), []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	path := write(t, dir, "depuis_flux.chto", chiffre.Bytes())
	out := filepath.Join(dir, "out.txt")
	if err := Decrypt(path, out, []byte("pw"), Options{}); err != nil {
		t.Fatalf("lecture sur disque d'un fichier écrit en flux: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(content, got) {
		t.Error("contenu différent")
	}
}

// TestFluxDossierSortTelQuel : sur un tube, une archive sort en tar. C'est ce
// qui permet le `| tar xf -` annoncé dans l'aide.
func TestFluxDossierSortTelQuel(t *testing.T) {
	src := arbre(t)
	enc := filepath.Join(t.TempDir(), "archive.chto")
	if err := Encrypt(src, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var tarBrut bytes.Buffer
	if err := DecryptStream(&tarBrut, f, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	// Ce qui sort doit être un tar lisible, et rien d'autre.
	if err := checkArchive(bytes.NewReader(tarBrut.Bytes())); err != nil {
		t.Fatalf("la sortie n'est pas un tar exploitable: %v", err)
	}

	dst := t.TempDir()
	if err := extractArchive(bytes.NewReader(tarBrut.Bytes()), dst); err != nil {
		t.Fatal(err)
	}
	compareArbres(t, src, dst)
}

func TestFluxRemplissageImpossible(t *testing.T) {
	err := EncryptStream(io.Discard, bytes.NewReader([]byte("x")), -1, []byte("pw"), Options{Pad: true})
	if err == nil {
		t.Fatal("le remplissage a été accepté sur une entrée de taille inconnue")
	}
	if !strings.Contains(err.Error(), "taille d'entrée connue") {
		t.Errorf("erreur peu explicite : %v", err)
	}
}

// --- Corps falsifié ou tronqué ------------------------------------------

// TestCorpsFalsifie : l'en-tête est déjà couvert par TestHeaderFalsifie. Ici on
// s'attaque au corps, c'est-à-dire à l'AEAD lui-même — un octet retourné doit
// faire échouer le déchiffrement et ne laisser aucune sortie derrière lui.
func TestCorpsFalsifie(t *testing.T) {
	dir := t.TempDir()
	clair := bytes.Repeat([]byte("contenu confidentiel. "), 500)
	in := write(t, dir, "clair.txt", clair)

	for _, c := range []struct {
		name string
		opts Options
	}{
		{"aes", Options{Algo: AlgoAES}},
		{"zstd", Options{Algo: AlgoAES, Comp: CompZstd}},
		{"cascade", Options{Algo: AlgoCascade}},
		{"remplissage", Options{Algo: AlgoAES, Pad: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			enc := filepath.Join(t.TempDir(), "ref.chto")
			if err := Encrypt(in, enc, []byte("pw"), c.opts); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(enc)
			if err != nil {
				t.Fatal(err)
			}

			// Un octet au milieu du corps, bien après l'en-tête.
			milieu := headerSizeV3 + (len(raw)-headerSizeV3)/2
			raw[milieu] ^= 0x01

			sous := t.TempDir()
			path := write(t, sous, "falsifie.chto", raw)
			out := filepath.Join(sous, "out")
			if err := Decrypt(path, out, []byte("pw"), Options{}); err == nil {
				t.Fatal("un corps falsifié a été accepté")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Error("une sortie a été laissée alors que le déchiffrement a échoué")
			}
			if err := Verify(path, []byte("pw"), Options{}); err == nil {
				t.Error("la vérification a validé un fichier falsifié")
			}
		})
	}
}

// TestFichierTronque : une coupure en cours de copie ou un disque plein
// produisent un .chto incomplet. Le dernier paquet scellé manque, donc l'AEAD
// doit refuser au lieu de rendre un clair partiel.
func TestFichierTronque(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", bytes.Repeat([]byte("a"), 200000))
	enc := filepath.Join(dir, "ref.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}

	for _, garde := range []int{headerSizeV3 + 1, len(raw) / 2, len(raw) - 1} {
		sous := t.TempDir()
		path := write(t, sous, "tronque.chto", raw[:garde])
		out := filepath.Join(sous, "out")
		if err := Decrypt(path, out, []byte("pw"), Options{}); err == nil {
			t.Errorf("un fichier tronqué à %d octets a été accepté", garde)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("tronqué à %d octets : une sortie a été laissée", garde)
		}
	}

	// Coupé exactement sur la frontière de l'en-tête, un fichier ordinaire est
	// indistinguable d'un fichier vide : sio ne produit aucun octet pour un
	// clair vide. On documente donc le comportement au lieu de prétendre le
	// détecter.
	sous := t.TempDir()
	path := write(t, sous, "entete_seul.chto", raw[:headerSizeV3])
	out := filepath.Join(sous, "out")
	if err := Decrypt(path, out, []byte("pw"), Options{}); err != nil {
		t.Fatalf("un fichier réduit à son en-tête devrait se lire comme un clair vide: %v", err)
	}
	if st, err := os.Stat(out); err != nil || st.Size() != 0 {
		t.Errorf("sortie inattendue: %v", err)
	}
}

// TestArchiveTronqueeALEntete : pour une archive, l'ambiguïté n'existe pas — un
// tar a toujours ses deux blocs de fin. Un dossier coupé à l'en-tête doit donc
// être refusé, et surtout ne pas produire un dossier vide sous le nom attendu.
func TestArchiveTronqueeALEntete(t *testing.T) {
	src := arbre(t)
	dir := t.TempDir()
	enc := filepath.Join(dir, "archive.chto")
	if err := Encrypt(src, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}

	path := write(t, dir, "tronque.chto", raw[:headerSizeV3])
	dst := filepath.Join(dir, "restaure")
	err = Decrypt(path, dst, []byte("pw"), Options{})
	if err == nil {
		t.Fatal("une archive réduite à son en-tête a été acceptée")
	}
	if !strings.Contains(err.Error(), "tronqué") {
		t.Errorf("erreur %q, attendu qu'elle parle de troncature", err)
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("un dossier vide a été créé sous le nom attendu")
	}
	if err := Verify(path, []byte("pw"), Options{}); err == nil {
		t.Error("la vérification a validé une archive tronquée")
	}
}

// TestDossierVideResteLisible est le pendant du test précédent : le contrôle de
// troncature ne doit pas refuser un dossier légitimement vide.
func TestDossierVideResteLisible(t *testing.T) {
	src := filepath.Join(t.TempDir(), "vide")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	enc := filepath.Join(dir, "vide.chto")
	if err := Encrypt(src, enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "restaure")
	if err := Decrypt(enc, dst, []byte("pw"), Options{}); err != nil {
		t.Fatalf("un dossier vide devrait rester lisible: %v", err)
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("le dossier restauré contient %d entrées, attendu 0", len(entries))
	}
}

// TestVerifyNEcritRien : la promesse de `verify` est de ne rien poser sur le
// disque, même sur un fichier sain.
func TestVerifyNEcritRien(t *testing.T) {
	src := arbre(t)
	work := t.TempDir()
	enc := filepath.Join(work, "archive.chto")
	if err := Encrypt(src, enc, []byte("pw"), Options{Comp: CompZstd}); err != nil {
		t.Fatal(err)
	}

	avant, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(enc, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	apres, err := os.ReadDir(work)
	if err != nil {
		t.Fatal(err)
	}
	if len(avant) != len(apres) {
		t.Errorf("le dossier contenait %d entrées avant la vérification, %d après", len(avant), len(apres))
	}
}

func TestDefaultKDFLabel(t *testing.T) {
	label := DefaultKDFLabel()
	if !strings.Contains(label, "argon2id") {
		t.Errorf("étiquette KDF %q, attendu qu'elle nomme argon2id", label)
	}
	// Elle doit décrire les paramètres réellement écrits dans les fichiers.
	if !strings.Contains(label, defaultArgonParams().String()) {
		t.Errorf("étiquette KDF %q, attendu qu'elle contienne %q", label, defaultArgonParams().String())
	}
}

func TestOptionsValidate(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{"vide", Options{}, false},
		{"zstd", Options{Comp: CompZstd}, false},
		{"remplissage seul", Options{Pad: true}, false},
		{"compression inconnue", Options{Comp: 99}, true},
		{"remplissage et gzip", Options{Pad: true, Comp: CompGzip}, true},
		{"remplissage et zstd", Options{Pad: true, Comp: CompZstd}, true},
	}
	for _, c := range cases {
		if err := c.opts.validate(); (err != nil) != c.wantErr {
			t.Errorf("%s : validate = %v, erreur attendue: %v", c.name, err, c.wantErr)
		}
	}
}

// TestRemplissageAvecCompressionEnLecture : un fichier qui annonce les deux à la
// fois ne peut pas venir de ce binaire, mais rien n'empêche de le fabriquer. La
// lecture doit rester cohérente — ici, échouer sur l'authentification, puisque
// les drapeaux entrent dans la dérivation de clé.
func TestRemplissageAvecCompressionEnLecture(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.txt", bytes.Repeat([]byte("a"), 1000))
	enc := filepath.Join(dir, "ref.chto")
	if err := Encrypt(in, enc, []byte("pw"), Options{Comp: CompZstd}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	raw[magicSize+versionSize] |= FlagPadded

	path := write(t, dir, "les_deux.chto", raw)
	if err := Decrypt(path, filepath.Join(dir, "out"), []byte("pw"), Options{}); err == nil {
		t.Error("un fichier annonçant compression et remplissage a été déchiffré")
	}
}

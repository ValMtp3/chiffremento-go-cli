package pkg

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Tests du format v4 : engagement de clé et enveloppe DEK/KEK.
//
// Deux propriétés nouvelles, et une qui ne doit pas se perdre en route :
//
//   - un chiffré n'est valide que sous une seule clé (engagement) ;
//   - la clé du contenu ne dépend plus du mot de passe, donc changer celui-ci
//     ne réécrit que l'en-tête ;
//   - l'en-tête reste authentifié : en modifier un octet doit toujours faire
//     échouer le déchiffrement, comme en v2 et v3.

const motDePasseV4 = "un-mot-de-passe-de-test"

// chiffreV4 produit un .chto v4 et rend son chemin.
func chiffreV4(t *testing.T, contenu []byte, opts Options) string {
	t.Helper()
	dir := t.TempDir()
	in := write(t, dir, "clair.bin", contenu)
	out := filepath.Join(dir, "chiffre.chto")
	if err := Encrypt(in, out, []byte(motDePasseV4), opts); err != nil {
		t.Fatalf("chiffrement: %v", err)
	}
	return out
}

// TestV4EstLeFormatProduit : les nouveaux fichiers sont en v4, et les versions
// précédentes restent lisibles (couvert par TestCompatibiliteV1 et V2).
func TestV4EstLeFormatProduit(t *testing.T) {
	chto := chiffreV4(t, []byte("contenu"), Options{})
	d, err := Inspect(chto)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != versionV4 {
		t.Errorf("version produite %d, attendu %d", d.Version, versionV4)
	}

	st, err := os.Stat(chto)
	if err != nil {
		t.Fatal(err)
	}
	// L'en-tête grossit de l'engagement (32 o) et de l'enveloppe (48 o). Le
	// vérifier ici évite qu'un champ soit ajouté sans que personne ne mesure ce
	// qu'il coûte sur un petit fichier.
	if st.Size() < int64(headerSizeV4) {
		t.Errorf("fichier de %d octets, plus court que son propre en-tête (%d)", st.Size(), headerSizeV4)
	}
}

// TestV4RoundTrip : toutes les combinaisons d'options doivent traverser le
// nouveau format sans perdre un octet.
func TestV4RoundTrip(t *testing.T) {
	contenu := bytes.Repeat([]byte("chiffremento v4 "), 500)

	cases := []struct {
		nom  string
		opts Options
	}{
		{"aes", Options{Algo: AlgoAES}},
		{"chacha", Options{Algo: AlgoChaCha}},
		{"cascade", Options{Algo: AlgoCascade}},
		{"zstd", Options{Algo: AlgoAES, Comp: CompZstd}},
		{"remplissage", Options{Algo: AlgoAES, Pad: true}},
		{"remplissage maximum", Options{Algo: AlgoAES, Pad: true, PadProfile: PadMaximum}},
		{"métadonnées", Options{Algo: AlgoAES, Metadata: MetadataMinimal}},
		{"kdf fort", Options{Algo: AlgoAES, KDF: KDFFort}},
	}

	for _, c := range cases {
		t.Run(c.nom, func(t *testing.T) {
			chto := chiffreV4(t, contenu, c.opts)
			out := filepath.Join(t.TempDir(), "clair.bin")
			if err := Decrypt(chto, out, []byte(motDePasseV4), Options{}); err != nil {
				t.Fatalf("déchiffrement: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, contenu) {
				t.Errorf("contenu altéré : %d octets rendus pour %d attendus", len(got), len(contenu))
			}
		})
	}
}

// TestV4MauvaisMotDePasse est le bénéfice visible de l'engagement : la clé est
// rejetée avant qu'on touche au contenu, et le message le dit.
func TestV4MauvaisMotDePasse(t *testing.T) {
	chto := chiffreV4(t, []byte("secret"), Options{})
	out := filepath.Join(t.TempDir(), "clair.bin")

	err := Decrypt(chto, out, []byte("ce-n-est-pas-le-bon"), Options{})
	if err == nil {
		t.Fatal("un mauvais mot de passe a été accepté")
	}
	if !errors.Is(err, ErrBadPassword) {
		t.Errorf("erreur %v, attendu ErrBadPassword", err)
	}
	// Rien ne doit avoir été écrit : le refus tombe avant l'ouverture de la
	// destination.
	if _, err := os.Lstat(out); err == nil {
		t.Error("une sortie a été créée alors que le mot de passe était faux")
	}
}

// TestV4EngagementSurLaCle : deux mots de passe distincts donnent deux
// engagements distincts, et l'engagement ne dépend que du couple (mot de passe,
// sel). C'est ce qui rend impossible un chiffré valide sous deux clés.
func TestV4EngagementSurLaCle(t *testing.T) {
	h := &header{
		Version: versionV4,
		Algo:    AlgoAES,
		Argon:   argonParams{Time: 1, Memory: 8 * 1024, Threads: 1},
		Salt:    bytes.Repeat([]byte{0x2a}, saltSize),
	}

	a, err := deriveMasterV4([]byte("mot-de-passe-a"), h)
	if err != nil {
		t.Fatal(err)
	}
	b, err := deriveMasterV4([]byte("mot-de-passe-b"), h)
	if err != nil {
		t.Fatal(err)
	}
	encore, err := deriveMasterV4([]byte("mot-de-passe-a"), h)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(a.commit, b.commit) {
		t.Error("deux mots de passe donnent le même engagement")
	}
	if !bytes.Equal(a.commit, encore.commit) {
		t.Error("le même mot de passe donne deux engagements différents")
	}
	if bytes.Equal(a.commit, a.kek) {
		t.Error("l'engagement et la clé d'enveloppe sont identiques : ils doivent être séparés")
	}
	if len(a.commit) != commitSize || len(a.kek) != 32 || len(a.nonce) != wrapNonceSize {
		t.Errorf("tailles inattendues : commit=%d kek=%d nonce=%d", len(a.commit), len(a.kek), len(a.nonce))
	}

	// Un sel différent change tout, sans quoi deux fichiers scellés avec le même
	// mot de passe partageraient leur engagement — un identifiant qui trahirait
	// leur origine commune à qui lit les en-têtes.
	autreSel := *h
	autreSel.Salt = bytes.Repeat([]byte{0x2b}, saltSize)
	c, err := deriveMasterV4([]byte("mot-de-passe-a"), &autreSel)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.commit, c.commit) {
		t.Error("le sel n'entre pas dans l'engagement")
	}
}

// TestV4EnTeteAltere : l'en-tête reste authentifié. Chaque octet compte, y
// compris ceux de l'engagement et de l'enveloppe.
func TestV4EnTeteAltere(t *testing.T) {
	chto := chiffreV4(t, []byte("contenu à protéger"), Options{Algo: AlgoAES})
	original, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}

	// Un octet par champ : version, drapeaux, algo, paramètres Argon2,
	// compression, sel, engagement, enveloppe.
	positions := []int{
		magicSize,                           // version
		magicSize + 1,                       // flags
		magicSize + 2,                       // algo
		magicSize + 3,                       // argonTime
		magicSize + 11,                      // argonThreads / compAlgo
		magicSize + 3 + argonParamsSize + 1, // compAlgo ou sel
		headerSizeV3 - 1,                    // dernier octet du sel
		headerSizeV3 + 4,                    // engagement
		headerSizeV3 + commitSize + 4,       // enveloppe
		headerSizeV4 - 1,                    // dernier octet de l'enveloppe
	}

	for _, pos := range positions {
		t.Run(string(rune('a'+pos%26))+"-octet-"+itoa(pos), func(t *testing.T) {
			altere := make([]byte, len(original))
			copy(altere, original)
			altere[pos] ^= 0x01

			chemin := filepath.Join(t.TempDir(), "altere.chto")
			if err := os.WriteFile(chemin, altere, 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "clair.bin")
			if err := Decrypt(chemin, out, []byte(motDePasseV4), Options{}); err == nil {
				t.Errorf("l'octet %d a été modifié sans que le déchiffrement échoue", pos)
			}
		})
	}
}

// TestV4CleDuContenuIndependanteDuMotDePasse est la propriété qui rend le
// changement de mot de passe instantané : la clé qui chiffre les données est
// tirée au hasard, pas dérivée du mot de passe.
func TestV4CleDuContenuIndependanteDuMotDePasse(t *testing.T) {
	dir := t.TempDir()
	in := write(t, dir, "clair.bin", []byte("le même contenu, le même mot de passe"))

	un := filepath.Join(dir, "un.chto")
	deux := filepath.Join(dir, "deux.chto")
	for _, out := range []string{un, deux} {
		if err := Encrypt(in, out, []byte(motDePasseV4), Options{Algo: AlgoAES}); err != nil {
			t.Fatal(err)
		}
	}

	a, err := os.ReadFile(un)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(deux)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Error("deux chiffrements du même fichier sont identiques : la clé de fichier n'est pas tirée au hasard")
	}
}

// itoa évite d'importer strconv pour trois caractères dans un nom de sous-test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestCompatibiliteV4 relit des fichiers v4 figés dans testdata, produits une
// fois pour toutes. Le jour où une v5 arrivera, c'est ce test qui dira si les
// fichiers d'aujourd'hui sont encore lisibles — les tests d'aller-retour, eux,
// chiffrent et déchiffrent avec le même code et ne verraient rien.
func TestCompatibiliteV4(t *testing.T) {
	const password = "reference-v4-password"
	cases := map[string]string{
		"v4_aes.chto":      "Fichier de reference v4 chiffre en AES-256-GCM.\n",
		"v4_chacha.chto":   "Fichier de reference v4 chiffre en ChaCha20-Poly1305.\n",
		"v4_cascade.chto":  "Fichier de reference v4 chiffre en mode cascade (parano).\n",
		"v4_aes_zstd.chto": "Fichier de reference v4 compresse en zstd puis chiffre en AES-256-GCM.\n",
		"v4_aes_meta.chto": "Fichier de reference v4 avec nom et date conserves.\n",
	}

	for name, attendu := range cases {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join("testdata", name)
			d, err := Inspect(src)
			if err != nil {
				t.Fatalf("inspection: %v", err)
			}
			if d.Version != versionV4 {
				t.Fatalf("version %d, attendu %d", d.Version, versionV4)
			}

			out := filepath.Join(t.TempDir(), "out.txt")
			if err := Decrypt(src, out, []byte(password), Options{}); err != nil {
				t.Fatalf("déchiffrement d'un fichier v4 de référence: %v", err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != attendu {
				t.Errorf("contenu inattendu:\nobtenu : %q\nattendu: %q", got, attendu)
			}

			// Le mauvais mot de passe doit être rejeté par l'engagement, pas par
			// une erreur d'authentification survenue plus loin.
			err = Decrypt(src, filepath.Join(t.TempDir(), "x"), []byte("mauvais"), Options{})
			if !errors.Is(err, ErrBadPassword) {
				t.Errorf("mauvais mot de passe : %v, attendu ErrBadPassword", err)
			}
		})
	}
}

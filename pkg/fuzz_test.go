package pkg

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzzing des deux fonctions qui lisent des octets venus de l'extérieur.
//
// C'est là que se logent les failles d'un format : readHeader interprète les
// premiers octets d'un fichier fourni par n'importe qui, et safeArchivePath des
// noms de chemins écrits par le producteur de l'archive. Un corpus découvert par
// la machine trouve des cas qu'on n'écrit pas à la main.
//
//	go test ./pkg -run '^$' -fuzz FuzzReadHeader -fuzztime 30s
//
// Le contrat vérifié n'est pas « ça ne plante pas » — le fuzzer le voit seul —
// mais « ça ne renvoie jamais un en-tête que la suite du code croirait valide ».

func FuzzReadHeader(f *testing.F) {
	// Graines : de vrais en-têtes, puis des variantes tronquées et bruitées.
	for _, name := range []string{"v1_aes.chto", "v2_aes.chto"} {
		if raw, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(raw)
			if len(raw) > headerSizeV1 {
				f.Add(raw[:headerSizeV1])
			}
		}
	}
	// Un en-tête v3 valide, construit ici pour ne pas dépendre d'un fichier.
	h := &header{Version: versionV3, Algo: AlgoAES, Argon: defaultArgonParams(), Comp: CompZstd, Salt: make([]byte, saltSize)}
	f.Add(h.marshal())
	f.Add([]byte(magicNumber))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := readHeader(bytes.NewReader(data))
		if err != nil {
			return
		}

		// Tout en-tête accepté doit être intégralement cohérent : c'est ce que
		// le reste du code suppose sans jamais le revérifier.
		if h.Version != versionV1 && h.Version != versionV2 && h.Version != versionV3 {
			t.Fatalf("version acceptée hors des versions connues : %d", h.Version)
		}
		if err := validateAlgo(h.Algo); err != nil {
			t.Fatalf("algorithme accepté alors qu'il est invalide : %v", err)
		}
		if err := validateComp(h.Comp); err != nil {
			t.Fatalf("compression acceptée alors qu'elle est invalide : %v", err)
		}
		if err := h.Argon.validate(); err != nil {
			t.Fatalf("paramètres Argon2 acceptés hors bornes : %v", err)
		}
		if h.Flags&^knownFlags != 0 {
			t.Fatalf("drapeau inconnu accepté : 0x%02x", h.Flags)
		}
		if h.padded() && h.Version < versionV3 {
			t.Fatal("remplissage accepté sur un format qui ne le connaît pas")
		}
		if len(h.Salt) != saltSize {
			t.Fatalf("sel de %d octets accepté, attendu %d", len(h.Salt), saltSize)
		}
		// Raw doit décrire exactement les octets lus : c'est lui qui authentifie
		// l'en-tête via la dérivation de clé.
		if len(h.Raw) > len(data) || !bytes.Equal(h.Raw, data[:len(h.Raw)]) {
			t.Fatal("Raw ne correspond pas aux octets réellement lus")
		}
	})
}

func FuzzSafeArchivePath(f *testing.F) {
	for _, seed := range []string{
		"a.txt", "sous/a.txt", "../evasion", "/etc/passwd", "a/../../x",
		"C:/x", "a\\b", "trop/profond/", strings.Repeat("a/", 70) + "f",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		// Les noms démesurés n'apprennent rien de plus et ralentissent le
		// fuzzer : un nom de chemin réel ne dépasse pas quelques kio.
		if len(name) > 4096 {
			return
		}
		rel, err := safeArchivePath(name)
		if err != nil {
			return
		}

		// Un chemin accepté ne doit jamais pouvoir sortir du dossier de
		// destination, quel que soit le dossier.
		const racine = "/tmp/destination"
		joint := filepath.Join(racine, filepath.FromSlash(rel))
		if !strings.HasPrefix(filepath.Clean(joint), filepath.Clean(racine)+string(filepath.Separator)) {
			t.Fatalf("%q accepté et pourtant joint hors de la racine : %q", name, joint)
		}
		if filepath.IsAbs(rel) || rel == "" || rel == "." {
			t.Fatalf("%q accepté et renvoyé sous une forme inexploitable : %q", name, rel)
		}
		for _, part := range strings.Split(rel, "/") {
			if part == ".." {
				t.Fatalf("%q accepté avec une remontée : %q", name, rel)
			}
		}
		if pathDepth(rel) > maxRecursionDepth {
			t.Fatalf("%q accepté malgré une profondeur de %d", name, pathDepth(rel))
		}
	})
}

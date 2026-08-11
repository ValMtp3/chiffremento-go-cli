package pkg

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// Benchmarks de débit.
//
// Ils servent deux choses : démontrer le gain de zstd sur gzip au lieu de le
// supposer, et attraper une régression de vitesse avant qu'elle n'arrive chez
// l'utilisateur.
//
//	go test ./pkg -run '^$' -bench . -benchtime 3x
//
// Deux familles, à ne pas confondre :
//
//   - BenchmarkPipeline mesure la seule chaîne compression + chiffrement, clés
//     déjà dérivées. C'est le nombre à regarder pour comparer les algorithmes,
//     et celui qui bougera si l'un d'eux régresse.
//   - BenchmarkEncryptStream mesure une opération complète, Argon2 compris. Il
//     colle à ce que vit l'utilisateur, mais la dérivation y coûte ~175 ms *par
//     conception* et écrase tout sur un fichier de quelques mégaoctets. Sur un
//     gros fichier, ce coût fixe disparaît dans le total.

// benchData produit des données réalistes : compressibles mais pas triviales,
// pour que la compression ait quelque chose à faire sans que le résultat soit
// une illusion d'optimisme.
func benchData(size int) []byte {
	motifs := [][]byte{
		[]byte("func chiffrer(entree, sortie string) error {\n\treturn nil\n}\n"),
		[]byte("2024-01-15T10:23:45Z INFO requête traitée en 12ms\n"),
		[]byte("lorem ipsum dolor sit amet, consectetur adipiscing elit\n"),
	}
	rng := rand.New(rand.NewSource(1))
	var buf bytes.Buffer
	buf.Grow(size)
	for buf.Len() < size {
		buf.Write(motifs[rng.Intn(len(motifs))])
		// Un peu d'aléa, sinon la compression fait des ratios irréalistes.
		var alea [16]byte
		rng.Read(alea[:])
		buf.Write(alea[:])
	}
	return buf.Bytes()[:size]
}

const benchSize = 8 << 20 // 8 Mio : assez pour sortir du bruit, assez court pour la CI

// BenchmarkPipeline isole la chaîne compression + chiffrement en fournissant
// des clés déjà dérivées : c'est le seul moyen de comparer gzip et zstd sans
// que les ~175 ms d'Argon2 noient l'écart.
func BenchmarkPipeline(b *testing.B) {
	data := benchData(benchSize)
	keys := &keySet{
		Key:   bytes.Repeat([]byte{0x2a}, 32),
		Inner: bytes.Repeat([]byte{0x2b}, 32),
		Outer: bytes.Repeat([]byte{0x2c}, 32),
	}

	cases := []struct {
		name       string
		algo, comp byte
	}{
		{"aes", AlgoAES, CompNone},
		{"chacha", AlgoChaCha, CompNone},
		{"cascade", AlgoCascade, CompNone},
		{"aes+gzip", AlgoAES, CompGzip},
		{"aes+zstd", AlgoAES, CompZstd},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				cw, err := initCipherWriter(writerOnly{io.Discard}, c.algo, keys)
				if err != nil {
					b.Fatal(err)
				}
				comp, err := initCompressWriter(cw, c.comp)
				if err != nil {
					b.Fatal(err)
				}
				var dst io.Writer = cw
				if comp != nil {
					dst = comp
				}
				if _, err := dst.Write(data); err != nil {
					b.Fatal(err)
				}
				if comp != nil {
					if err := comp.Close(); err != nil {
						b.Fatal(err)
					}
				}
				if err := cw.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncryptStream(b *testing.B) {
	data := benchData(benchSize)
	password := []byte("pw")

	cases := []struct {
		name string
		opts Options
	}{
		{"aes", Options{Algo: AlgoAES}},
		{"chacha", Options{Algo: AlgoChaCha}},
		{"cascade", Options{Algo: AlgoCascade}},
		{"aes+gzip", Options{Algo: AlgoAES, Comp: CompGzip}},
		{"aes+zstd", Options{Algo: AlgoAES, Comp: CompZstd}},
		{"aes+remplissage", Options{Algo: AlgoAES, Pad: true}},
	}

	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if err := EncryptStream(io.Discard, bytes.NewReader(data), int64(len(data)), password, c.opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecryptStream(b *testing.B) {
	data := benchData(benchSize)
	password := []byte("pw")

	for _, c := range []struct {
		name string
		opts Options
	}{
		{"aes", Options{Algo: AlgoAES}},
		{"aes+gzip", Options{Algo: AlgoAES, Comp: CompGzip}},
		{"aes+zstd", Options{Algo: AlgoAES, Comp: CompZstd}},
	} {
		var chiffre bytes.Buffer
		if err := EncryptStream(&chiffre, bytes.NewReader(data), int64(len(data)), password, c.opts); err != nil {
			b.Fatal(err)
		}
		raw := chiffre.Bytes()

		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if err := DecryptStream(io.Discard, bytes.NewReader(raw), password, Options{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkArchive mesure l'empaquetage d'un dossier : beaucoup de petits
// fichiers, donc dominé par les appels système et non par le chiffrement.
func BenchmarkArchive(b *testing.B) {
	root := b.TempDir()
	contenu := benchData(16 << 10)
	for i := 0; i < 200; i++ {
		sous := filepath.Join(root, "d"+string(rune('a'+i%26)))
		if err := os.MkdirAll(sous, 0755); err != nil {
			b.Fatal(err)
		}
		name := filepath.Join(sous, "f"+string(rune('a'+i%26))+".txt")
		if err := os.WriteFile(name, contenu, 0644); err != nil {
			b.Fatal(err)
		}
	}

	plan, err := scanDirectory(root)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(plan.total)
	for i := 0; i < b.N; i++ {
		if err := writeArchive(io.Discard, plan, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeriveKeys mesure le coût voulu de la dérivation. Il n'est pas là
// pour être optimisé mais surveillé : s'il s'effondre, c'est que les paramètres
// Argon2 ont été affaiblis par accident.
func BenchmarkDeriveKeys(b *testing.B) {
	h := &header{Version: currentVersion, Algo: AlgoAES, Argon: defaultArgonParams(), Salt: make([]byte, saltSize)}
	h.marshal()
	for i := 0; i < b.N; i++ {
		keys, err := deriveKeys([]byte("motdepasse"), h)
		if err != nil {
			b.Fatal(err)
		}
		keys.wipe()
	}
}

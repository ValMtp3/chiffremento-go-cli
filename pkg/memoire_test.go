package pkg

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestArgon2RendSaMemoire : Argon2 alloue 256 Mio, inutiles dès la dérivation
// finie. Sans restitution explicite, le runtime Go les gardait : l'empreinte
// restait à ~272 Mo pendant tout le chiffrement d'un gros fichier, et le pic
// doublait (~544 Mo) quand deux dérivations se suivaient — changement de mot
// de passe, chiffrement puis relecture avant suppression.
func TestArgon2RendSaMemoire(t *testing.T) {
	if testing.Short() {
		t.Skip("dérivation Argon2 de 256 Mio")
	}
	params := defaultArgonParams()
	sel := make([]byte, saltSize)

	if _, err := deriveKey([]byte("mot de passe"), sel, params); err != nil {
		t.Fatal(err)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Ce que le processus garde du système : le tas réservé, moins ce qui a
	// été rendu. Sans restitution, le bloc d'Argon2 y reste en entier.
	garde := int64(m.HeapSys) - int64(m.HeapReleased)
	plafond := int64(params.Memory) * 1024 / 4 // moins d'un quart du bloc
	if garde > plafond {
		t.Errorf("%d Mio de tas gardés après la dérivation, attendu moins de %d Mio",
			garde>>20, plafond>>20)
	}
}

// arbreDePetitsFichiers crée n fichiers de quelques octets.
func arbreDePetitsFichiers(t *testing.T, n int) string {
	t.Helper()
	racine := t.TempDir()
	for i := range n {
		if err := os.WriteFile(filepath.Join(racine, fmt.Sprintf("f%04d.txt", i)), []byte("contenu"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return racine
}

// octetsAlloues mesure ce que fn alloue au total.
func octetsAlloues(fn func()) uint64 {
	var avant, apres runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&avant)
	fn()
	runtime.ReadMemStats(&apres)
	return apres.TotalAlloc - avant.TotalAlloc
}

// TestArchiveSansTamponParFichier : chaque io.Copy allouait un tampon de
// 32 Kio, soit 640 Mo de déchets pour 20 000 fichiers — l'empreinte d'un
// dossier montait à ~420 Mo contre ~276 pour un fichier seul. Un tampon unique
// par opération suffit : la copie est séquentielle.
func TestArchiveSansTamponParFichier(t *testing.T) {
	if raceEnabled {
		t.Skip("le détecteur de courses ajoute ses propres allocations")
	}
	const n = 400
	racine := arbreDePetitsFichiers(t, n)
	plan, err := scanDirectory(racine)
	if err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	alloueEcriture := octetsAlloues(func() {
		if err := writeArchive(&archive, plan, nil); err != nil {
			t.Fatal(err)
		}
	})
	dest := filepath.Join(t.TempDir(), "sortie")
	if err := os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	alloueExtraction := octetsAlloues(func() {
		if err := extractArchive(bytes.NewReader(archive.Bytes()), dest); err != nil {
			t.Fatal(err)
		}
	})

	// Le tar lui-même, les en-têtes et les appels système allouent un peu
	// par fichier ; un tampon de 32 Kio par fichier dépasse largement ce seuil.
	const seuilParFichier = 8 << 10
	if parFichier := alloueEcriture / n; parFichier > seuilParFichier {
		t.Errorf("archivage : %d octets alloués par fichier, attendu moins de %d", parFichier, seuilParFichier)
	}
	if parFichier := alloueExtraction / n; parFichier > seuilParFichier {
		t.Errorf("extraction : %d octets alloués par fichier, attendu moins de %d", parFichier, seuilParFichier)
	}
}

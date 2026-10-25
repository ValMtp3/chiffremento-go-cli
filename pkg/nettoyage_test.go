package pkg

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestNettoyageReessaieUneFois : sous Windows, supprimer un fichier qu'une
// écriture vient de lâcher peut échouer un court instant. Le nettoyage
// réessaie alors une fois, après un délai borné, et le temporaire disparaît.
func TestNettoyageReessaieUneFois(t *testing.T) {
	temp := filepath.Join(t.TempDir(), ".chto-tmp-essai")
	if err := os.WriteFile(temp, []byte("clair"), 0o600); err != nil {
		t.Fatal(err)
	}
	essais := 0
	ancien := supprimerTout
	supprimerTout = func(p string) error {
		essais++
		if essais == 1 {
			return errors.New("fichier encore ouvert")
		}
		return os.RemoveAll(p)
	}
	t.Cleanup(func() { supprimerTout = ancien })

	if err := trackTemp(temp); err != nil {
		t.Fatal(err)
	}
	nettoyerTemporaires()
	if essais != 2 {
		t.Errorf("%d essais de suppression, attendu 2", essais)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Errorf("le temporaire est resté après le second essai (Stat : %v)", err)
	}
}

// TestNettoyageUnSeulEssaiSiReussi : une suppression réussie n'est pas
// répétée, et le nettoyage n'attend pas.
func TestNettoyageUnSeulEssaiSiReussi(t *testing.T) {
	temp := filepath.Join(t.TempDir(), ".chto-tmp-essai")
	if err := os.WriteFile(temp, []byte("clair"), 0o600); err != nil {
		t.Fatal(err)
	}
	essais := 0
	ancien := supprimerTout
	supprimerTout = func(p string) error { essais++; return os.RemoveAll(p) }
	t.Cleanup(func() { supprimerTout = ancien })
	if err := trackTemp(temp); err != nil {
		t.Fatal(err)
	}
	nettoyerTemporaires()
	if essais != 1 {
		t.Errorf("%d essais de suppression, attendu 1", essais)
	}
}

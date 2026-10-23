package zxcvbn

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"chiffremento-cli/internal/zxcvbn/scoring"
)

// Années de référence figées : zxcvbn compare les dates à l'année en cours
// (scoring.ReferenceYear = time.Now().Year()), donc les chiffres changeraient
// chaque 1er janvier. Les tests amont ont été écrits en 2019 ; parite.json a
// été produit avec la v1.0.1 en 2026.
const (
	anneeReferenceAmont  = 2019
	anneeReferenceParite = 2026
)

// toleranceRelative absorbe l'écart d'un dernier chiffre entre architectures :
// sur arm64 Go fusionne x*y+z (FMA), pas sur amd64.
const toleranceRelative = 1e-12

func proches(attendu, obtenu float64) bool {
	return math.Abs(attendu-obtenu) <= toleranceRelative*math.Abs(attendu)
}

// fixerAnneeReference fige l'année de référence le temps du test.
func fixerAnneeReference(t testing.TB, annee int) {
	t.Helper()
	avant := scoring.ReferenceYear
	scoring.ReferenceYear = annee
	t.Cleanup(func() { scoring.ReferenceYear = avant })
}

// TestPariteAvecV101 compare la copie interne à la v1.0.1 d'origine.
// testdata/parite.json a été produit une fois avec la bibliothèque amont :
// mêmes mots de passe, mêmes guesses , même score.
func TestPariteAvecV101(t *testing.T) {
	fixerAnneeReference(t, anneeReferenceParite)
	octets, err := os.ReadFile(filepath.Join("testdata", "parite.json"))
	if err != nil {
		t.Fatalf("lecture de la référence : %v", err)
	}
	var references []struct {
		Password string  `json:"password"`
		Guesses  float64 `json:"guesses"`
		Score    int     `json:"score"`
	}
	if err := json.Unmarshal(octets, &references); err != nil {
		t.Fatalf("lecture du JSON de référence : %v", err)
	}
	if len(references) == 0 {
		t.Fatal("référence vide")
	}
	for _, ref := range references {
		t.Run(ref.Password, func(t *testing.T) {
			got := PasswordStrength(ref.Password, nil)
			if !proches(ref.Guesses, got.Guesses) {
				t.Errorf("guesses = %v, attendu %v", got.Guesses, ref.Guesses)
			}
			if got.Score != ref.Score {
				t.Errorf("score = %d, attendu %d", got.Score, ref.Score)
			}
		})
	}
}

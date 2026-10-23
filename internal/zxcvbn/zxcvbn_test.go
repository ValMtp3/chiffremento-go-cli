package zxcvbn

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"

	"chiffremento-cli/internal/zxcvbn/internal/verif/assert"
	"chiffremento-cli/internal/zxcvbn/internal/verif/require"
)

func TestPasswordStrength(t *testing.T) {
	fixerAnneeReference(t, anneeReferenceAmont)
	var testdata []struct {
		Password string         `json:"password"`
		Guesses  float64        `json:"guesses"`
		Score    int            `json:"score"`
		Sequence []*match.Match `json:"sequence"`
	}

	b, err := os.ReadFile(filepath.Join("testdata", "output.json"))
	require.NoError(t, err)

	err = json.Unmarshal(b, &testdata)
	require.NoError(t, err)

	for _, td := range testdata {
		t.Run(td.Password, func(t *testing.T) {
			// map character positions to rune position
			runeMap := make(map[int]int, len(td.Password))
			c := 0
			for i := range td.Password {
				runeMap[i] = c
				c++
			}
			runeMap[len(td.Password)] = c
			s := passwordStrength(td.Password, nil, frequency.Anglais())
			if len(s.Sequence) == len(td.Sequence) {
				for j := range td.Sequence {
					expect, _ := json.Marshal(td.Sequence[j])
					got, _ := json.Marshal(s.Sequence[j])
					msg := func(f string) string {
						return fmt.Sprintf("Password %+q, field %s: expect=%s got=%s",
							td.Password,
							f,
							string(expect),
							string(got))
					}
					if !assert.Equal(t, td.Sequence[j].I, runeMap[s.Sequence[j].I], msg("i")) {
						return
					}
					if !assert.Equal(t, td.Sequence[j].J, runeMap[s.Sequence[j].J+1]-1, msg("j")) {
						t.Logf("runeMap %v\n", runeMap)
						return
					}
					if !assert.Equal(t, td.Sequence[j].Pattern, s.Sequence[j].Pattern, msg("pattern")) {
						return
					}
					if !assert.Equal(t, td.Sequence[j].Token, s.Sequence[j].Token, msg("token")) {
						return
					}
					if !assert.Equal(t, td.Sequence[j].Guesses, s.Sequence[j].Guesses, msg("guesses")) {
						return
					}
				}
			} else {
				b, _ := json.Marshal(td.Sequence)
				t.Errorf("Expected sequence:\n%s\nGot:\n%s\n",
					string(b),
					match.ToString(s.Sequence))
				return
			}
			// Tolérance d'un millionième de milliardième : sur arm64 le compilateur fusionne
			// x*y+z (FMA) et l'arrondi diffère d'un cheveu de la référence JavaScript.
			if !proches(td.Guesses, s.Guesses) {
				t.Errorf("guesses = %v, attendu %v", s.Guesses, td.Guesses)
			}
			assert.Equal(t, td.Score, s.Score, "Wrong score")
		})
	}

}

// Cas limites : une chaîne vide vaut au plus un essai ; de l'UTF-8 invalide
// n'est pas évalué (Result vide, 0 essai) plutôt que de paniquer.
func TestCornerCases(t *testing.T) {
	if g := PasswordStrength("", nil).Guesses; g > 1 {
		t.Errorf("chaîne vide : %v essais, au plus 1 attendu", g)
	}
	if g := PasswordStrength("wen\x8e\xc6", nil).Guesses; g != 0 {
		t.Errorf("UTF-8 invalide : %v essais, 0 attendu", g)
	}
}

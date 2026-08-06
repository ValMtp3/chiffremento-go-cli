package main

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func demoModel(ratio float64) *progressModel {
	var done atomic.Int64
	total := int64(14_900_000)
	done.Store(int64(float64(total) * ratio))

	m := newProgressModel(jobInfo{
		Action: "chiffrement",
		In:     "rapport-annuel.pdf",
		Out:    "rapport-annuel.pdf.chto",
		Size:   total,
		AEAD:   "aes-256-gcm",
		KDF:    "argon2id  m=256MiB t=3 p=4",
		Salt:   "16 o aléatoires · en-tête lié à la clé",
	}, &done)
	return m
}

// TestRenduLargeurConstante garantit la promesse de la DA : la mise en page ne
// bouge pas d'un terminal à l'autre. Toutes les lignes du cadre doivent avoir
// exactement la même largeur, quel que soit l'avancement.
func TestRenduLargeurConstante(t *testing.T) {
	for _, ratio := range []float64{0, 0.01, 0.5, 0.74, 0.999, 1} {
		m := demoModel(ratio)
		lines := strings.Split(strings.Trim(m.View(), "\n"), "\n")

		var width int
		for i, line := range lines {
			w := lipgloss.Width(line)
			if i == 0 {
				continue // la ligne de titre est hors cadre
			}
			if width == 0 {
				width = w
				continue
			}
			if w != width {
				t.Errorf("ratio %.2f : la ligne %d fait %d colonnes au lieu de %d\n%q",
					ratio, i, w, width, line)
			}
		}
		// lipgloss compte le padding dans Width() ; seule la bordure s'ajoute.
		if width != contentWidth+2 {
			t.Errorf("ratio %.2f : cadre de %d colonnes, attendu %d", ratio, width, contentWidth+4)
		}
	}
}

// TestRenduSansCouleur vérifie qu'aucun emoji ni glyphe exotique ne s'est
// glissé dans l'affichage : seuls le box-drawing simple ligne et les blocs
// pleins sont autorisés, ils existent dans toutes les polices mono.
func TestRenduSansCouleur(t *testing.T) {
	autorises := "─│┌┐└┘█░·…✓"
	view := demoModel(0.5).View()

	for _, r := range view {
		if r < 0x80 || strings.ContainsRune(autorises, r) {
			continue
		}
		// Les lettres accentuées restent évidemment acceptables.
		if r >= 0xC0 && r <= 0x17F {
			continue
		}
		t.Errorf("caractère non prévu par la DA dans l'affichage : %q (U+%04X)", r, r)
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		0:          "0 o",
		512:        "512 o",
		1024:       "1.0 ko",
		14_900_000: "14.2 Mo",
	}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, attendu %q", in, got, want)
		}
	}
}

package main

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
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

// TestAnimationVisible : sur un petit fichier, l'opération est finie avant la
// première image. La barre doit malgré tout se dérouler sur minDuration, sans
// jamais dépasser la progression réelle.
func TestAnimationVisible(t *testing.T) {
	var done atomic.Int64
	total := int64(1000)
	m := newProgressModel(jobInfo{Action: "chiffrement", Size: total}, &done)

	// Opération instantanée : 100 % des octets traités dès le départ.
	done.Store(total)
	m.opDone = true

	if r := m.displayRatio(); r > 0.2 {
		t.Errorf("la barre est déjà à %.0f%% à t=0 : l'animation ne serait pas visible", r*100)
	}

	m.start = m.start.Add(-minDuration / 2)
	if r := m.displayRatio(); r < 0.4 || r > 0.6 {
		t.Errorf("à mi-durée la barre devrait être à ~50%%, elle est à %.0f%%", r*100)
	}

	m.start = m.start.Add(-minDuration)
	if r := m.displayRatio(); r != 1 {
		t.Errorf("après minDuration la barre devrait être pleine, elle est à %.0f%%", r*100)
	}
}

// TestAnimationNeDepassePasLeReel : sur un gros fichier lent, c'est la
// progression réelle qui pilote, jamais le minuteur.
func TestAnimationNeDepassePasLeReel(t *testing.T) {
	var done atomic.Int64
	total := int64(1000)
	m := newProgressModel(jobInfo{Size: total}, &done)

	done.Store(300) // 30 % réellement traités
	m.start = m.start.Add(-10 * minDuration)

	if r := m.displayRatio(); r != 0.3 {
		t.Errorf("la barre affiche %.0f%% alors que seuls 30%% sont traités", r*100)
	}
}

// TestDureeEcranReelle fait tourner le vrai runJob sans terminal et mesure sa
// durée. Ce test a attrapé un blocage : quand le compteur d'octets n'atteint
// pas exactement le total — au déchiffrement, l'en-tête est lu avant que le
// compteur soit branché — l'écran ne se fermait jamais.
func TestDureeEcranReelle(t *testing.T) {
	teaOptions = []tea.ProgramOption{tea.WithInput(nil), tea.WithOutput(io.Discard)}
	defer func() { teaOptions = nil }()

	cases := map[string]func(p func(int64, int64)) error{
		"compteur complet":   func(p func(int64, int64)) error { p(1000, 1000); return nil },
		"compteur incomplet": func(p func(int64, int64)) error { p(1, 1000000); return nil },
		"aucune progression": func(p func(int64, int64)) error { return nil },
	}

	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if err := runJob(jobInfo{Action: "test", In: "/etc/hosts", Success: "ok"}, op); err != nil {
				t.Fatal(err)
			}
			d := time.Since(start)
			switch {
			case d < minDuration:
				t.Errorf("écran fermé en %v : l'animation n'aurait pas été visible", d)
			case d > 3*minDuration:
				t.Errorf("écran resté ouvert %v : blocage", d)
			}
		})
	}
}

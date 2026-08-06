package main

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Écran de progression animé.
//
// huh sait présenter un formulaire mais pas animer, donc cet écran-là est un
// modèle Bubble Tea à part entière. Le chiffrement tourne dans sa propre
// goroutine et ne fait que déposer un compteur d'octets ; l'animation le lit à
// chaque frame. Elle ne peut donc jamais ralentir la copie.

const (
	frameRate  = 66 * time.Millisecond // ~15 images/seconde
	scrambleN  = 14                    // nombre de groupes d'octets affichés
	barWidth   = 30
	appVersion = "v2.0"
)

type tickMsg time.Time
type doneMsg struct{ err error }

// jobInfo décrit l'opération en cours, telle qu'affichée à l'utilisateur.
// Toutes ces valeurs sont réelles : elles viennent des constantes du paquet
// crypto ou de l'en-tête du fichier, jamais d'un texte décoratif.
type jobInfo struct {
	Action string // "chiffrement" ou "déchiffrement"
	In     string
	Out    string
	Size   int64
	AEAD   string
	KDF    string
	Salt   string
}

type progressModel struct {
	info jobInfo

	// done est écrit par la goroutine de chiffrement et lu par l'animation.
	done  *atomic.Int64
	total int64

	start    time.Time
	finished bool
	err      error

	rng *rand.Rand
}

func newProgressModel(info jobInfo, done *atomic.Int64) *progressModel {
	return &progressModel{
		info:  info,
		done:  done,
		total: info.Size,
		start: time.Now(),
		// Aléa purement décoratif : math/rand suffit largement, inutile de
		// consommer de l'entropie cryptographique pour du scintillement.
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (m *progressModel) Init() tea.Cmd { return tick() }

func tick() tea.Cmd {
	return tea.Tick(frameRate, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		if m.finished {
			return m, tea.Quit
		}
		return m, tick()
	case doneMsg:
		m.finished = true
		m.err = msg.err
		return m, tea.Quit
	case tea.KeyMsg:
		// On n'interrompt pas une opération en cours : un .chto à moitié écrit
		// n'aurait aucune valeur, et l'écriture atomique attend le commit.
		if msg.Type == tea.KeyCtrlC {
			return m, nil
		}
	}
	return m, nil
}

func (m *progressModel) View() string {
	done := m.done.Load()
	ratio := 0.0
	if m.total > 0 {
		ratio = float64(done) / float64(m.total)
	} else if m.finished {
		ratio = 1
	}
	if ratio > 1 {
		ratio = 1
	}

	var b strings.Builder

	const sizeCol = 9
	nameWidth := innerWidth - labelWidth - sizeCol

	b.WriteString(styleLabel.Render("entrée") + styleText.Render(pad(base(m.info.In), nameWidth)) +
		styleDim.Render(rightAlign(humanSize(m.info.Size), sizeCol)) + "\n")
	b.WriteString(styleLabel.Render("sortie") + styleText.Render(pad(base(m.info.Out), nameWidth+sizeCol)) + "\n\n")

	b.WriteString(styleLabel.Render("aead") + styleAccent.Render(m.info.AEAD) + "\n")
	b.WriteString(styleLabel.Render("kdf") + styleAccent.Render(m.info.KDF) + "\n")
	b.WriteString(styleLabel.Render("sel") + styleDim.Render(m.info.Salt) + "\n\n")

	b.WriteString(m.scramble(ratio) + "\n")
	b.WriteString(m.bar(ratio, done))

	title := styleDim.Render("chiffremento ") + styleAccent.Render(m.info.Action)
	box := styleBox.Width(contentWidth).Render(b.String())
	return "\n" + lipgloss.JoinVertical(lipgloss.Left,
		"  "+title+styleFaint.Render("  "+appVersion),
		box,
	) + "\n"
}

// scramble matérialise la transformation en cours : à gauche les octets déjà
// chiffrés (blocs pleins), au curseur l'octet en cours de transformation, à
// droite les octets encore en clair, retirés au sort à chaque image.
func (m *progressModel) scramble(ratio float64) string {
	cursor := int(ratio * scrambleN)
	parts := make([]string, scrambleN)
	for i := range parts {
		switch {
		case i < cursor:
			parts[i] = styleAccent.Render("██")
		case i == cursor && !m.finished:
			parts[i] = styleAccent.Render(fmt.Sprintf("%02x", m.rng.Intn(256)))
		case m.finished:
			parts[i] = styleAccent.Render("██")
		default:
			parts[i] = styleFaint.Render(fmt.Sprintf("%02x", m.rng.Intn(256)))
		}
	}
	return strings.Join(parts, " ")
}

func (m *progressModel) bar(ratio float64, done int64) string {
	filled := int(ratio * barWidth)
	if m.finished {
		filled = barWidth
		ratio = 1
	}
	bar := styleAccent.Render(strings.Repeat("█", filled)) +
		styleFaint.Render(strings.Repeat("░", barWidth-filled))

	elapsed := time.Since(m.start).Seconds()
	rate := ""
	if elapsed > 0.2 && done > 0 {
		rate = humanSize(int64(float64(done)/elapsed)) + "/s"
	}
	return fmt.Sprintf("%s %s %s", bar,
		styleText.Render(rightAlign(fmt.Sprintf("%d%%", int(ratio*100)), 4)),
		styleDim.Render(rate))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d o", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %co", float64(n)/float64(div), "kMGT"[exp])
}

// base raccourcit un chemin à son nom de fichier : un chemin absolu long
// ferait déborder la colonne, et le répertoire n'apporte rien ici.
func base(p string) string { return filepath.Base(p) }

// pad et rightAlign comptent en colonnes affichées, pas en octets : les
// libellés sont accentués et un « é » pèse deux octets pour une seule colonne.
func pad(s string, w int) string {
	r := []rune(s)
	if len(r) > w && w > 1 {
		return string(r[:w-1]) + "…"
	}
	return s + strings.Repeat(" ", max(0, w-len(r)))
}

func rightAlign(s string, w int) string {
	return strings.Repeat(" ", max(0, w-len([]rune(s)))) + s
}

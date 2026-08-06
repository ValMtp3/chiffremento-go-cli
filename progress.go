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
	frameRate = 66 * time.Millisecond // ~15 images/seconde
	scrambleN = 14                    // nombre de groupes d'octets affichés
	barWidth  = 30

	// minDuration : durée minimale d'affichage de l'écran. Sur un petit
	// fichier, le chiffrement est terminé avant la première image et
	// l'animation clignoterait sans qu'on voie rien.
	//
	// C'est bien l'affichage qui est ralenti, pas le chiffrement : celui-ci
	// tourne à pleine vitesse dans sa goroutine, et la barre ne dépasse jamais
	// la progression réelle (voir displayRatio). Aucun effet en mode CLI, qui
	// n'utilise pas cet écran.
	minDuration = 2 * time.Second

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
	// Success : la ligne affichée une fois l'opération réussie.
	Success string
}

type progressModel struct {
	info jobInfo

	// done est écrit par la goroutine de chiffrement et lu par l'animation.
	done  *atomic.Int64
	total int64

	start time.Time
	// opDone : le chiffrement est terminé. finished : l'écran a fini de
	// dérouler son animation et peut se fermer.
	opDone   bool
	finished bool
	err      error

	rng *rand.Rand
}

// displayRatio est l'avancement *affiché*. Il ne dépasse jamais l'avancement
// réel — on ne ment pas sur ce qui est fait — mais il ne va pas plus vite que
// minDuration, pour que l'animation reste visible sur un petit fichier.
//
// Sur un gros fichier, elapsed/minDuration dépasse vite le réel et c'est donc
// le réel qui pilote : le bridage disparaît de lui-même.
func (m *progressModel) displayRatio() float64 {
	real := 0.0
	switch {
	case m.opDone:
		// L'opération terminée fait autorité, quoi que dise le compteur
		// d'octets. Sans ce cas, l'écran ne se fermerait jamais dès que le
		// compte n'atteint pas exactement le total : au déchiffrement, les
		// 36 octets d'en-tête sont lus avant que le compteur soit branché,
		// donc il plafonne à taille-36.
		real = 1
	case m.total > 0:
		real = float64(m.done.Load()) / float64(m.total)
	}
	if real > 1 {
		real = 1
	}

	paced := float64(time.Since(m.start)) / float64(minDuration)
	if paced < real {
		return paced
	}
	return real
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
		// On ne ferme l'écran que quand l'opération est finie *et* que la barre
		// a fini de se remplir, sinon on n'aurait rien vu passer.
		if m.opDone && m.displayRatio() >= 1 {
			m.finished = true
			return m, tea.Quit
		}
		return m, tick()
	case doneMsg:
		m.opDone = true
		m.err = msg.err
		if m.err != nil {
			// Une erreur n'a aucune raison d'attendre la fin de l'animation.
			m.finished = true
			return m, tea.Quit
		}
		// Pas de tick() ici : la chaîne lancée par Init tourne toujours. En
		// relancer une seconde doublerait le nombre de rendus par seconde.
		return m, nil
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
	ratio := m.displayRatio()

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
		case i == cursor && ratio < 1:
			// L'octet en cours de transformation, retiré au sort à chaque image.
			parts[i] = styleAccent.Render(fmt.Sprintf("%02x", m.rng.Intn(256)))
		default:
			parts[i] = styleFaint.Render(fmt.Sprintf("%02x", m.rng.Intn(256)))
		}
	}
	return strings.Join(parts, " ")
}

func (m *progressModel) bar(ratio float64, done int64) string {
	filled := int(ratio * barWidth)
	if filled > barWidth {
		filled = barWidth
	}
	bar := styleAccent.Render(strings.Repeat("█", filled)) +
		styleFaint.Render(strings.Repeat("░", barWidth-filled))

	// Le débit est calculé sur les octets réellement traités, pas sur la barre
	// bridée. Une fois l'opération finie il n'a plus de sens, on le remplace
	// par la taille traitée.
	elapsed := time.Since(m.start).Seconds()
	right := ""
	switch {
	case m.opDone:
		right = humanSize(m.total)
	case elapsed > 0.2 && done > 0:
		right = humanSize(int64(float64(done)/elapsed)) + "/s"
	}

	return fmt.Sprintf("%s %s %s", bar,
		styleText.Render(rightAlign(fmt.Sprintf("%d%%", int(ratio*100)), 4)),
		styleDim.Render(right))
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

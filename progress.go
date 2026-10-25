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
//
// En plein écran, c'est un sous-écran de l'hôte : il s'affiche dans le cadre,
// à sa largeur. Hors plein écran (TERM=dumb), runJobSeul lui donne un
// programme à lui et la largeur historique.

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
	//
	// Quatre secondes est un choix assumé, pas un réglage à optimiser : c'est le
	// temps qu'il faut pour que l'animation soit *regardée* et que le
	// récapitulatif du cadre (aead, kdf, sel) se lise en entier. Le seuil
	// s'efface de lui-même sur un gros fichier, où la progression réelle est
	// plus lente que le rythme imposé.
	minDuration = 4 * time.Second

	// largeurMinProgression : en dessous, la ligne d'octets (41 colonnes)
	// ne tient plus dans le cadre des détails. C'est l'intérieur du plus
	// petit cadre de l'hôte ; plus étroit (terminal minuscule), l'écran se
	// dessine à cette largeur et l'hôte coupe ce qui dépasse.
	largeurMinProgression = largeurCadreMin - bordureEtMarge
	// cadreDetails : la bordure (1 colonne) et le padding (2 colonnes) de
	// styleBox, de chaque côté.
	cadreDetails = 6
	// largeurDebit : la place réservée à droite de la barre pour le débit ou
	// la taille, au plus « 1023.9 Mo/s ».
	largeurDebit = 11
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
	// Ecrit : l'opération pose Out sur le disque (chiffrer, déchiffrer).
	// Une vérification n'écrit rien.
	Ecrit bool
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

	// largeur : les colonnes données par l'hôte (l'intérieur du cadre).
	largeur int
	// fin rend l'erreur de l'opération quand elle se termine. Nil dans les
	// tests qui pilotent opDone à la main.
	fin <-chan error
	// autonome : hors plein écran (programme à lui, TERM=dumb), l'écran
	// affiche lui-même son titre et garde sa largeur historique, quelle que
	// soit la taille du terminal. Dans l'hôte, la barre du haut porte le titre
	// et la largeur suit le cadre.
	autonome bool
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

func newProgressModel(info jobInfo, done *atomic.Int64, largeur int) *progressModel {
	return &progressModel{
		info:    info,
		done:    done,
		total:   info.Size,
		start:   time.Now(),
		largeur: largeur,
		// Aléa purement décoratif : math/rand suffit largement, inutile de
		// consommer de l'entropie cryptographique pour du scintillement.
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Init lance l'animation et, quand l'opération est branchée, l'attente de sa
// fin : une commande qui bloque sur le canal puis rend doneMsg. Passer par une
// commande de l'écran, plutôt qu'un Send de la goroutine de l'opération, garantit
// que la fin arrive à cet écran-là : un Send pourrait être traité avant que
// l'hôte ait ouvert l'écran, et se perdre.
func (m *progressModel) Init() tea.Cmd {
	if m.fin == nil {
		return tick()
	}
	return tea.Batch(tick(), attendreFin(m.fin))
}

func attendreFin(fin <-chan error) tea.Cmd {
	return func() tea.Msg { return doneMsg{err: <-fin} }
}

// Titre et Touches font de l'écran un sous-écran de l'hôte. Aucune touche
// propre : seules les globales (aide, Ctrl+C) s'appliquent.
func (m *progressModel) Titre() string   { return "progression" }
func (m *progressModel) Touches() string { return "" }

// gardeEchap : l'écriture est lancée, Échap ne doit pas l'abandonner à moitié.
// L'hôte lui passe donc la touche, que l'écran ignore. Ctrl+C, lui, quitte
// toujours : le nettoyage des temporaires rend la destination intacte.
func (m *progressModel) gardeEchap() bool { return true }

func tick() tea.Cmd {
	return tea.Tick(frameRate, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *progressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Bubble Tea envoie la taille du terminal au démarrage, même hors de
		// l'hôte : seule celle du cadre compte.
		if !m.autonome {
			m.largeur = msg.Width
		}
		return m, nil
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
		// En mode brut, Ctrl+C arrive comme une touche et non comme un signal.
		// On le transforme en interruption : runJobSeul nettoie alors les
		// temporaires et sort en 130. Rien n'est perdu — l'écriture atomique
		// n'a pas encore touché la destination. Dans l'hôte, Ctrl+C n'arrive
		// pas jusqu'ici : l'hôte le traite lui-même.
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Interrupt
		}
	}
	return m, nil
}

func (m *progressModel) View() string {
	done := m.done.Load()
	ratio := m.displayRatio()

	var b strings.Builder

	// Toute la largeur suit le cadre : le cadre des détails prend exactement
	// la place donnée, et chaque valeur est coupée à ce qui reste. Une valeur
	// trop longue repliée ajouterait une ligne et ferait sauter la barre.
	largeur := max(m.largeur, largeurMinProgression)
	texte := largeur - cadreDetails
	valeur := texte - labelWidth

	const sizeCol = 9
	nameWidth := valeur - sizeCol

	b.WriteString(styleLabel.Render("entrée") + styleText.Render(pad(base(m.info.In), nameWidth)) +
		styleDim.Render(rightAlign(humanSize(m.info.Size), sizeCol)) + "\n")
	b.WriteString(styleLabel.Render("sortie") + styleText.Render(pad(base(m.info.Out), valeur)) + "\n\n")

	b.WriteString(styleLabel.Render("aead") + styleAccent.Render(pad(m.info.AEAD, valeur)) + "\n")
	b.WriteString(styleLabel.Render("kdf") + styleAccent.Render(pad(m.info.KDF, valeur)) + "\n")
	b.WriteString(styleLabel.Render("sel") + styleDim.Render(pad(m.info.Salt, valeur)) + "\n\n")

	b.WriteString(m.scramble(ratio) + "\n")
	b.WriteString(m.bar(ratio, done, texte))

	// Width compte le padding mais pas la bordure (convention lipgloss).
	box := styleBox.Width(largeur - 2).Render(b.String())
	if !m.autonome {
		return box
	}
	title := styleDim.Render("chiffremento ") + styleAccent.Render(m.info.Action)
	return "\n" + lipgloss.JoinVertical(lipgloss.Left,
		"  "+title+styleFaint.Render("  "+versionAffichee(version)),
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

// bar dessine la barre sur barWidth colonnes, moins si le cadre le plus étroit
// ne laisse pas la place du pourcentage et du débit à côté.
func (m *progressModel) bar(ratio float64, done int64, texte int) string {
	longueur := max(min(barWidth, texte-len(" 100% ")-largeurDebit), 0)
	filled := min(int(ratio*float64(longueur)), longueur)
	bar := styleAccent.Render(strings.Repeat("█", filled)) +
		styleFaint.Render(strings.Repeat("░", longueur-filled))

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

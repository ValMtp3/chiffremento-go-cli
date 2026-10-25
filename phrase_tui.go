package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"chiffremento-cli/pkg"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// Écran de la phrase de passe générée.
//
// Proposé à l'étape du mot de passe quand on chiffre : plutôt que d'inventer un
// secret, l'utilisateur en reçoit un d'environ 128 bits (pkg/passphrase.go).
// La phrase s'ouvre masquée — un partage d'écran ou un regard par-dessus
// l'épaule ne doit pas la saisir — et ne s'affiche qu'à la demande. Elle peut
// être copiée ; le presse-papier n'est jamais vidé par l'outil, et l'écran le
// dit pour que l'utilisateur sache où traîne son secret.

// issueEcranPhrase dit comment l'utilisateur a quitté l'écran.
type issueEcranPhrase int

const (
	issueAucune issueEcranPhrase = iota
	issueContinuer
	issueRetour
)

// longueurMasque est la largeur du masque, quelle que soit la phrase.
const longueurMasque = 24

type modelePhrase struct {
	phrase  pkg.Phrase
	mots    int
	visible bool
	message string
	issue   issueEcranPhrase
	// dansLeCadre : affiché par l'hôte, dont la barre du bas annonce déjà les
	// touches ; la ligne d'aide sous la phrase ferait doublon.
	dansLeCadre bool

	copier  func(string) error
	generer func(int) (pkg.Phrase, error)
}

// newModelePhrase tire une première phrase de mots mots. copier et generer
// sont injectés : les tests ne touchent ni au vrai presse-papier ni à l'aléa.
func newModelePhrase(mots int, copier func(string) error, generer func(int) (pkg.Phrase, error)) (*modelePhrase, error) {
	m := &modelePhrase{mots: mots, copier: copier, generer: generer}
	if err := m.nouvellePhrase(); err != nil {
		return nil, err
	}
	return m, nil
}

// nouvellePhrase tire une phrase et la remet sous masque : une phrase neuve
// n'a pas été demandée à l'affichage.
func (m *modelePhrase) nouvellePhrase() error {
	p, err := m.generer(m.mots)
	if err != nil {
		return err
	}
	m.phrase, m.visible = p, false
	return nil
}

func (m *modelePhrase) Init() tea.Cmd { return nil }

// Titre et Touches font de l'écran un sous-écran de l'hôte. Échap n'y figure
// pas : dans le cadre, l'hôte la prend pour revenir au menu.
func (m *modelePhrase) Titre() string { return "phrase générée" }

func (m *modelePhrase) Touches() string {
	return "a afficher  c copier  r nouvelle  +/- mots  ⏎ continuer  ← revenir"
}

func (m *modelePhrase) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	touche, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	m.message = ""
	switch touche.String() {
	// En quittant, la phrase repasse sous masque : Bubble Tea laisse sa
	// dernière image dans le terminal, et une phrase affichée y resterait en
	// clair — défilement, capture, journal tmux.
	case "ctrl+c":
		m.visible = false
		return m, tea.Interrupt
	case "enter":
		m.visible = false
		m.issue = issueContinuer
		return m, tea.Quit
	case "esc", "left":
		m.visible = false
		m.issue = issueRetour
		return m, tea.Quit
	case "a":
		m.visible = !m.visible
	case "c":
		m.copierPhrase()
	case "r":
		m.regenerer(m.mots)
	case "+":
		if m.mots < pkg.MaxMotsPhrase {
			m.regenerer(m.mots + 1)
		}
	case "-":
		if m.mots > pkg.MinMotsPhrase {
			m.regenerer(m.mots - 1)
		}
	}
	return m, nil
}

func (m *modelePhrase) copierPhrase() {
	if m.copier == nil {
		m.message = "copie indisponible ici"
		return
	}
	if err := m.copier(m.phrase.Texte); err != nil {
		m.message = "copie impossible : " + err.Error()
		return
	}
	m.message = "copiée — elle reste dans le presse-papier : vide-le une fois la phrase enregistrée"
}

// regenerer garde l'ancienne phrase si le tirage échoue : mieux vaut une
// phrase valide affichée qu'un écran vide, et l'échec se dit.
func (m *modelePhrase) regenerer(mots int) {
	precedent := m.mots
	m.mots = mots
	if err := m.nouvellePhrase(); err != nil {
		m.mots = precedent
		m.message = "nouvelle phrase impossible : " + err.Error()
	}
}

func (m *modelePhrase) View() string {
	var b strings.Builder
	b.WriteString("\n  " + styleText.Render("phrase de passe générée") + "\n\n")

	// Masque de longueur fixe : autant de points que de caractères donnerait
	// la longueur de la phrase, donc un indice sur les mots tirés.
	affichee := strings.Repeat("•", longueurMasque)
	if m.visible {
		affichee = m.phrase.Texte
	}
	b.WriteString("  " + styleAccent.Render(affichee) + "\n\n")

	b.WriteString("  " + styleDim.Render(fmt.Sprintf("%d mots · %.0f bits · %s",
		m.mots, m.phrase.Bits, crackTime(m.phrase.Bits))) + "\n")
	if m.message != "" {
		b.WriteString("  " + styleText.Render(m.message) + "\n")
	}
	if m.dansLeCadre {
		return b.String()
	}
	b.WriteString("\n  " + styleFaint.Render(
		"a afficher/masquer · c copier · r nouvelle · +/- mots · entrée continuer · échap retour") + "\n")
	return b.String()
}

// etapePhrase propose une phrase générée et ne rend la main qu'une fois
// l'utilisateur certain de l'avoir enregistrée. errRetour ramène aux options.
//
// La question de confirmation part sur « pas encore » : un fichier chiffré
// avec une phrase que personne n'a notée est perdu, et la touche Entrée
// machinale ne doit pas suffire à le sceller.
func etapePhrase() (pkg.Phrase, error) {
	m, err := newModelePhrase(pkg.DefautMotsPhrase, clipboard.WriteAll, pkg.GenererPhrase)
	if err != nil {
		return pkg.Phrase{}, err
	}
	for {
		m.issue = issueAucune
		if err := afficherPhrase(m); err != nil {
			return pkg.Phrase{}, err
		}
		if m.issue != issueContinuer {
			return pkg.Phrase{}, errRetour
		}

		enregistree := false
		champ := questionFermee(
			"as-tu enregistré cette phrase ?",
			"dans un gestionnaire de mots de passe ou sur papier\n"+
				"sans elle, le fichier chiffré est définitivement perdu",
			"oui, je l'ai enregistrée", "pas encore", &enregistree)
		form := huh.NewForm(huh.NewGroup(champ)).
			WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
		err := lancerEtapeNommee("phrase enregistrée", form, champ)
		if err != nil && !errors.Is(err, errRetour) {
			return pkg.Phrase{}, err
		}
		if err == nil && enregistree {
			return m.phrase, nil
		}
		// « pas encore » ou retour : on revient à la phrase, inchangée.
	}
}

// afficherPhrase montre l'écran de la phrase : dans le cadre de l'hôte s'il
// y en a un, sinon dans un programme aux réglages communs (30 images/s,
// sortie sur stderr).
func afficherPhrase(m *modelePhrase) error {
	if h := hoteDuCadre(); h != nil {
		m.dansLeCadre = true
		_, err := h.afficher(m)
		// Échap et Ctrl+C sont pris par l'hôte avant l'écran, qui n'a donc
		// pas remasqué la phrase lui-même : on le fait ici, quelle que soit
		// l'issue.
		m.visible = false
		return err
	}
	if _, err := tea.NewProgram(m, optionsProgramme()...).Run(); err != nil {
		if errors.Is(err, tea.ErrInterrupted) {
			return huh.ErrUserAborted
		}
		return err
	}
	return nil
}

// doGenpass écrit une phrase sur la sortie standard, seule sur sa ligne, pour
// qu'elle se passe telle quelle à un autre outil. L'entropie va sur stderr.
func doGenpass(mots int) error {
	p, err := pkg.GenererPhrase(mots)
	if err != nil {
		return err
	}
	// Une écriture ratée (tube fermé) doit faire échouer la commande : sinon
	// `chiffremento -mode genpass | pbcopy` sortirait en 0 sans rien copier.
	if _, err := fmt.Println(p.Texte); err != nil {
		return fmt.Errorf("écriture de la phrase: %w", err)
	}
	fmt.Fprintln(os.Stderr, styleDim.Render(fmt.Sprintf("%d mots · %.0f bits · %s",
		mots, p.Bits, crackTime(p.Bits))))
	return nil
}

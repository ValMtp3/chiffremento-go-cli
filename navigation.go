package main

import (
	"errors"
	"os"
	"slices"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// errRetour signale que l'utilisateur veut revenir sur une décision déjà
// prise. Elle ne sort jamais de runTUI : chaque boucle du parcours l'attrape et
// réaffiche l'écran précédent, avec les réponses déjà données.
var errRetour = errors.New("retour à la décision précédente")

// formKeyMap donne aux formulaires la grammaire de l'explorateur de fichiers,
// la seule que l'interface enseignait déjà : ↑↓ pour parcourir, → pour entrer,
// ← pour remonter. Une décision se prend donc comme on choisit un fichier.
//
// ← et → sont libres dans une liste verticale : huh ne les lie (Left et Right)
// qu'aux listes « inline », et l'interface n'en a aucune. Ils restent en
// revanche pris dans un champ texte, où ils déplacent le curseur, et dans
// l'explorateur, où ils ouvrent et referment un dossier ; là, le retour garde
// shift+tab — voir retourDepuis.
func formKeyMap() *huh.KeyMap {
	k := huh.NewDefaultKeyMap()

	k.Select.Up = key.NewBinding(key.WithKeys("up", "k", "ctrl+k", "ctrl+p"), key.WithHelp("↑", "monter"))
	k.Select.Down = key.NewBinding(key.WithKeys("down", "j", "ctrl+j", "ctrl+n"), key.WithHelp("↓", "descendre"))
	k.Select.Prev = key.NewBinding(key.WithKeys("left", "shift+tab"), key.WithHelp("←", "revenir"))
	k.Select.Next = key.NewBinding(key.WithKeys("right", "enter", "tab"), key.WithHelp("→", "valider"))
	k.Select.Submit = key.NewBinding(key.WithKeys("enter"), key.WithHelp("entrée", "valider"))
	// Le filtre n'apporte rien sur deux ou trois options, et il coûterait cher :
	// une fois sa saisie ouverte, ← lui appartiendrait et la touche de retour
	// cesserait de reculer sans que rien ne l'explique. On le prive de touche
	// et d'entrée d'aide plutôt que de le désactiver : huh le réactive de
	// lui-même à chaque fois que le champ reprend le focus.
	k.Select.Filter = key.NewBinding(key.WithKeys(), key.WithHelp("", ""))

	k.Note.Prev = key.NewBinding(key.WithKeys("left", "shift+tab"), key.WithHelp("←", "revenir"))
	k.Note.Next = key.NewBinding(key.WithKeys("right", "enter", "tab"), key.WithHelp("→", "continuer"))
	k.Note.Submit = key.NewBinding(key.WithKeys("enter"), key.WithHelp("entrée", "valider"))

	// Dans un champ texte, ← et → appartiennent au curseur : le retour y reste
	// shift+tab, et l'écran le rappelle.
	k.Input.Prev = key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "revenir"))
	k.Input.Next = key.NewBinding(key.WithKeys("enter", "tab"), key.WithHelp("entrée", "valider"))
	k.Input.Submit = key.NewBinding(key.WithKeys("enter"), key.WithHelp("entrée", "valider"))

	k.FilePicker.Up = key.NewBinding(key.WithKeys("up", "k", "ctrl+k", "ctrl+p"), key.WithHelp("↑", "monter"))
	k.FilePicker.Down = key.NewBinding(key.WithKeys("down", "j", "ctrl+j", "ctrl+n"), key.WithHelp("↓", "descendre"))
	k.FilePicker.Open = key.NewBinding(key.WithKeys("l", "right", "enter"), key.WithHelp("→", "ouvrir"))
	k.FilePicker.Back = key.NewBinding(key.WithKeys("h", "backspace", "left", "esc"), key.WithHelp("←", "remonter"))
	k.FilePicker.Prev = key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "revenir"))
	k.FilePicker.Next = key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "valider"))
	k.FilePicker.Submit = key.NewBinding(key.WithKeys("enter"), key.WithHelp("entrée", "choisir"))

	return k
}

// questionFermee pose une question à deux réponses sous forme de liste
// verticale, et non avec le champ « confirm » de huh : celui-ci aligne deux
// boutons côte à côte et prend ←/→ pour passer de l'un à l'autre. Ces deux
// touches sont désormais celles du parcours — reculer, avancer — et une
// grammaire unique vaut mieux qu'un raccourci qui change de sens d'une question
// à l'autre.
//
// L'ordre des appels compte, comme souvent avec huh : les options d'abord,
// l'accès à la valeur ensuite — voir reponseAccessor.
func questionFermee(titre, description, siOui, siNon string, valeur *bool) huh.Field {
	return huh.NewSelect[string]().
		Title(titre).
		Description(description).
		Options(huh.NewOption(siOui, siOui), huh.NewOption(siNon, siNon)).
		Accessor(reponseAccessor{valeur: valeur, siOui: siOui, siNon: siNon})
}

func ouiNon(titre, description string, valeur *bool) huh.Field {
	return questionFermee(titre, description, "oui", "non", valeur)
}

// reponseAccessor présente un booléen à huh comme l'un des deux libellés de la
// liste.
//
// Un Select[bool] serait plus direct, mais il ouvrirait la liste amputée de sa
// première réponse. En posant ses options, huh cale le défilement sur la valeur
// courante du champ : `false` désigne déjà « non », donc la liste s'ouvrirait
// décalée d'un cran et « oui » resterait hors de l'écran. Une valeur qui ne
// correspond à aucune option — ici la chaîne vide, valeur nulle de string —
// laisse le défilement en haut, et le curseur se pose ensuite sur la bonne
// ligne. Même raison pour l'ordre : les listes de l'interface posent toutes
// leurs options avant leur valeur.
type reponseAccessor struct {
	valeur       *bool
	siOui, siNon string
}

func (a reponseAccessor) Get() string {
	if *a.valeur {
		return a.siOui
	}
	return a.siNon
}

func (a reponseAccessor) Set(choix string) { *a.valeur = choix == a.siOui }

// retourDepuis dit par quelles touches on quitte un écran vers le précédent, et
// comment l'écran l'annonce. Le champ passé est celui sur lequel s'ouvre le
// formulaire : c'est le seul endroit d'où « précédent » veut dire « écran
// précédent » plutôt que « champ précédent ».
func retourDepuis(ancre huh.Field) (touches []string, rappel string) {
	switch ancre.(type) {
	case *huh.Input, *huh.Text, *huh.FilePicker:
		// ← y a déjà un rôle — déplacer le curseur, remonter d'un dossier — et
		// le lui prendre casserait la saisie.
		return []string{"shift+tab"}, "shift+tab  revenir à l'étape précédente"
	}
	return []string{"left", "shift+tab"}, "←  revenir à l'étape précédente"
}

// etapeModel enveloppe un formulaire pour lui ajouter ce que huh ne fait pas :
// en sortir par l'arrière. huh navigue entre les champs d'un même formulaire,
// or chaque écran du parcours en est un à lui seul — arrivé sur son premier
// champ, la touche « précédent » ne mène nulle part, et huh la désactive même
// à cet endroit. On l'intercepte donc avant lui pour rendre la main à l'écran
// d'avant.
type etapeModel struct {
	form    *huh.Form
	ancre   huh.Field // champ depuis lequel un retour quitte le formulaire
	touches []string  // touches qui déclenchent ce retour
	rappel  string
	retour  bool
}

func newEtapeModel(form *huh.Form, ancre huh.Field) *etapeModel {
	touches, rappel := retourDepuis(ancre)
	return &etapeModel{form: form, ancre: ancre, touches: touches, rappel: rappel}
}

func (m *etapeModel) Init() tea.Cmd { return m.form.Init() }

func (m *etapeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && m.form.GetFocusedField() == m.ancre && slices.Contains(m.touches, k.String()) {
		m.retour = true
		return m, tea.Quit
	}
	modele, cmd := m.form.Update(msg)
	m.form = modele.(*huh.Form)
	return m, cmd
}

func (m *etapeModel) View() string {
	vue := m.form.View()
	// Formulaire terminé : huh rend une vue vide pour effacer son écran, et on
	// ne rajoute surtout pas une ligne à ce moment-là.
	if vue == "" {
		return vue
	}
	// Le rappel n'apparaît que sur l'ancre, seul endroit où il est vrai :
	// ailleurs, la touche annoncée remonte d'une question et non d'un écran, et
	// l'aide de huh le dit déjà.
	if m.form.GetFocusedField() != m.ancre {
		return vue
	}
	return vue + styleFaint.Render("  "+m.rappel) + "\n"
}

// lancerEtape affiche un formulaire et distingue trois issues : terminé,
// abandonné (Ctrl+C), ou retour à l'écran précédent — errRetour.
//
// Une ancre nulle vaut « pas d'écran avant celui-ci » : le formulaire tourne
// alors comme d'habitude, sous le programme de huh.
func lancerEtape(form *huh.Form, ancre huh.Field) error {
	// TERM=dumb : huh bascule tout seul en mode accessible, une suite de
	// questions en texte brut sans écran à intercepter. On le laisse faire —
	// mieux vaut pas de retour arrière qu'une interface illisible.
	if ancre == nil || os.Getenv("TERM") == "dumb" {
		return form.Run()
	}

	// Run() pose ces deux commandes lui-même. Ici c'est nous qui tenons le
	// programme : sans elles, le formulaire terminé ne quitterait jamais.
	form.SubmitCmd = tea.Quit
	form.CancelCmd = tea.Interrupt

	// Les mêmes options que huh : la sortie va sur stderr, pour ne pas mêler
	// l'interface à ce qu'un appelant pourrait lire sur stdout.
	m := newEtapeModel(form, ancre)
	final, err := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithReportFocus()).Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return huh.ErrUserAborted
	}
	if err != nil {
		return err
	}
	if final.(*etapeModel).retour {
		return errRetour
	}
	if form.State == huh.StateAborted {
		return huh.ErrUserAborted
	}
	return nil
}

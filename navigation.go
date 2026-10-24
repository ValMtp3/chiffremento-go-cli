package main

import (
	"errors"
	"os"
	"slices"
	"sync"

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
	// Submit porte les mêmes touches que Next, sans quoi → cesse d'avancer sur le
	// dernier champ d'un écran. huh y désactive Next et n'active que Submit
	// (field_select.go : Next.SetEnabled(!p.IsLast()), Submit.SetEnabled(p.IsLast())),
	// et les deux mènent à la même branche : jamais les deux à la fois, donc
	// aucun conflit à les lier à la même touche.
	//
	// Sans ça, → ne faisait rien là où il n'y a qu'une question — l'écrasement, la
	// suppression après coup, le brouillage — ni sur le choix de la cible, qui
	// termine le premier écran : « parcourir les fichiers » validé avec → laissait
	// l'écran en place, et l'explorateur restait hors d'atteinte.
	k.Select.Submit = key.NewBinding(key.WithKeys("right", "enter", "tab"), key.WithHelp("→", "valider"))
	// Le filtre n'apporte rien sur deux ou trois options, et il coûterait cher :
	// une fois sa saisie ouverte, ← lui appartiendrait et la touche de retour
	// cesserait de reculer sans que rien ne l'explique. On le prive de touche
	// et d'entrée d'aide plutôt que de le désactiver : huh le réactive de
	// lui-même à chaque fois que le champ reprend le focus.
	k.Select.Filter = key.NewBinding(key.WithKeys(), key.WithHelp("", ""))

	k.Note.Prev = key.NewBinding(key.WithKeys("left", "shift+tab"), key.WithHelp("←", "revenir"))
	k.Note.Next = key.NewBinding(key.WithKeys("right", "enter", "tab"), key.WithHelp("→", "continuer"))
	k.Note.Submit = key.NewBinding(key.WithKeys("right", "enter", "tab"), key.WithHelp("→", "continuer"))

	// Dans un champ texte, ← et → appartiennent au curseur : le retour y reste
	// shift+tab, et l'écran le rappelle.
	k.Input.Prev = key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "revenir"))
	k.Input.Next = key.NewBinding(key.WithKeys("enter", "tab"), key.WithHelp("entrée", "valider"))
	k.Input.Submit = key.NewBinding(key.WithKeys("enter"), key.WithHelp("entrée", "valider"))

	k.FilePicker.Up = key.NewBinding(key.WithKeys("up", "k", "ctrl+k", "ctrl+p"), key.WithHelp("↑", "monter"))
	k.FilePicker.Down = key.NewBinding(key.WithKeys("down", "j", "ctrl+j", "ctrl+n"), key.WithHelp("↓", "descendre"))
	k.FilePicker.Open = key.NewBinding(key.WithKeys("l", "right", "enter"), key.WithHelp("→", "ouvrir"))
	k.FilePicker.Back = key.NewBinding(key.WithKeys("h", "backspace", "left", "esc"), key.WithHelp("←", "remonter"))
	// Close porte aussi Échap, et huh le teste avant Back : Échap refermait
	// l'explorateur et passait au champ suivant — le formulaire se validait
	// sans fichier choisi. On le prive de touche, comme le filtre des listes,
	// pour qu'Échap remonte d'un dossier comme Back l'annonce.
	k.FilePicker.Close = key.NewBinding(key.WithKeys(), key.WithHelp("", ""))
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

// verrouSaisie protège le mot de passe tapé à l'écran des options.
//
// huh calcule la description d'un champ — ici l'indicateur de robustesse —
// dans une tea.Cmd, donc sur une autre goroutine que celle qui reçoit les
// frappes (field_input.go, updateDescriptionMsg). Sans verrou, ce calcul lisait
// la chaîne pendant que la frappe suivante la réécrivait : une course que
// go test -race a relevée dans le parcours de bout en bout.
//
// Un seul verrou pour tout le programme suffit : un seul formulaire est à
// l'écran à la fois.
var verrouSaisie sync.Mutex

// saisieVerrouillee donne à huh l'accès à une saisie par le verrou. La valeur
// reste une string ordinaire : le reste du code la lit directement, sur la
// goroutine de l'interface ou après la fin du formulaire, là où personne
// d'autre ne l'écrit.
type saisieVerrouillee struct{ valeur *string }

func (a saisieVerrouillee) Get() string {
	verrouSaisie.Lock()
	defer verrouSaisie.Unlock()
	return *a.valeur
}

func (a saisieVerrouillee) Set(v string) {
	verrouSaisie.Lock()
	defer verrouSaisie.Unlock()
	*a.valeur = v
}

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
//
// Dans le plein écran, etapeModel est aussi le sous-écran que l'hôte affiche
// dans son cadre : il annonce ses touches et dit lesquelles il garde.
type etapeModel struct {
	form    *huh.Form
	ancre   huh.Field // champ depuis lequel un retour quitte le formulaire
	premier huh.Field // champ qui a le focus à l'ouverture
	touches []string  // touches qui déclenchent ce retour
	rappel  string
	retour  bool
	// dansLeCadre : affiché par l'hôte, dont la barre du bas annonce déjà le
	// retour ; le rappel sous le formulaire ferait doublon.
	dansLeCadre bool
}

func newEtapeModel(form *huh.Form, ancre huh.Field) *etapeModel {
	touches, rappel := retourDepuis(ancre)
	return &etapeModel{form: form, ancre: ancre, premier: form.GetFocusedField(), touches: touches, rappel: rappel}
}

func (m *etapeModel) Init() tea.Cmd { return m.form.Init() }

func (m *etapeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && m.form.GetFocusedField() == m.ancre && slices.Contains(m.touches, k.String()) {
		m.retour = true
		return m, tea.Quit
	}
	// huh n'écoute plus les tailles suivantes dès qu'une largeur lui a été
	// imposée (form.go : « if f.width == 0 ») : on la lui redonne donc à
	// chaque changement. Dans le cadre, c'est la largeur intérieure que
	// l'hôte transmet ; hors du cadre, celle du terminal, comme avant.
	if taille, ok := msg.(tea.WindowSizeMsg); ok {
		m.form = m.form.WithWidth(taille.Width)
	}
	modele, cmd := m.form.Update(msg)
	m.form = modele.(*huh.Form)
	return m, cmd
}

// Titre est vide : huh ne dit pas le titre d'un champ, et l'opération en
// cours suffit au fil d'Ariane, qui omet une étape vide.
func (m *etapeModel) Titre() string { return "" }

// Touches annonce celles du champ qui a le focus. Le retour n'est annoncé que
// là où il mène quelque part : depuis l'ancre vers l'écran d'avant, ou vers
// la question précédente du même écran.
func (m *etapeModel) Touches() string {
	champ := m.form.GetFocusedField()
	retourPossible := m.ancre != nil || champ != m.premier
	var touches string
	switch champ.(type) {
	case *huh.Input, *huh.Text:
		touches = "⏎ valider"
		if retourPossible {
			touches += "  shift+tab revenir"
		}
	case *huh.FilePicker:
		touches = "↑↓ choisir  → ouvrir  ← remonter  ⏎ choisir"
		if retourPossible {
			touches += "  shift+tab revenir"
		}
	default:
		touches = "↑↓ choisir  → valider"
		if retourPossible {
			touches += "  ← revenir"
		}
	}
	return touches
}

// saisitDuTexte : dans un champ texte, ? est un caractère comme un autre —
// une phrase de passe peut en contenir. L'hôte n'ouvre donc pas l'aide.
func (m *etapeModel) saisitDuTexte() bool {
	switch m.form.GetFocusedField().(type) {
	case *huh.Input, *huh.Text:
		return true
	}
	return false
}

// gardeEchap : dans l'explorateur, Échap remonte d'un dossier (formKeyMap).
// L'hôte ne la transforme donc pas en retour au menu.
func (m *etapeModel) gardeEchap() bool {
	_, explorateur := m.form.GetFocusedField().(*huh.FilePicker)
	return explorateur
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
	if m.dansLeCadre || m.form.GetFocusedField() != m.ancre {
		return vue
	}
	return vue + styleFaint.Render("  "+m.rappel) + "\n"
}

// imagesParSeconde plafonne la cadence de rendu. bubbletea redessine par
// défaut à 60 images/s, même quand rien ne change : ~250 réveils par seconde
// au repos, ce que macOS compte en premier pour la batterie. À 30, les réveils
// sont divisés par deux, et une frappe s'affiche au pire 33 ms plus tard —
// imperceptible. L'animation de progression (15 images/s) n'est pas touchée.
const imagesParSeconde = 30

// optionsProgramme reprend les options que huh pose par défaut — sortie sur
// stderr, pour ne pas mêler l'interface à ce qu'un appelant lirait sur stdout,
// et suivi du focus — et y ajoute la cadence. WithProgramOptions remplace les
// options de huh au lieu de s'y ajouter : les oublier enverrait l'interface
// sur stdout.
func optionsProgramme() []tea.ProgramOption {
	return []tea.ProgramOption{tea.WithOutput(os.Stderr), tea.WithReportFocus(), tea.WithFPS(imagesParSeconde)}
}

// lancerChamp affiche un champ isolé comme le fait field.Run de huh, mais
// avec les options du projet — et dans le cadre de l'hôte s'il y en a un.
func lancerChamp(champ huh.Field) error {
	return lancerEtape(huh.NewForm(huh.NewGroup(champ).WithShowHelp(false)).WithShowHelp(false), nil)
}

// hoteCourant est l'écran hôte du plein écran, nil en dehors. Il est posé
// avant le lancement du parcours et n'est plus modifié ensuite : le parcours
// le lit sans verrou.
var hoteCourant *hote

// lancerEtape affiche un formulaire et distingue trois issues : terminé,
// abandonné (Ctrl+C), ou retour à l'écran précédent — errRetour. Dans le
// cadre de l'hôte, Échap ajoute une quatrième issue : errMenu.
//
// Une ancre nulle vaut « pas d'écran avant celui-ci » : le formulaire tourne
// alors comme d'habitude, sous le programme de huh.
func lancerEtape(form *huh.Form, ancre huh.Field) error {
	// TERM=dumb : huh bascule tout seul en mode accessible, une suite de
	// questions en texte brut sans écran à intercepter. On le laisse faire —
	// mieux vaut pas de retour arrière qu'une interface illisible.
	dumb := os.Getenv("TERM") == "dumb"
	if h := hoteCourant; h != nil && !dumb {
		return lancerEtapeDansLeCadre(h, form, ancre)
	}
	if ancre == nil || dumb {
		return form.WithProgramOptions(optionsProgramme()...).Run()
	}

	// Run() pose ces deux commandes lui-même. Ici c'est nous qui tenons le
	// programme : sans elles, le formulaire terminé ne quitterait jamais.
	form.SubmitCmd = tea.Quit
	form.CancelCmd = tea.Interrupt

	// Les mêmes options que huh : la sortie va sur stderr, pour ne pas mêler
	// l'interface à ce qu'un appelant pourrait lire sur stdout.
	m := newEtapeModel(form, ancre)
	final, err := tea.NewProgram(m, optionsProgramme()...).Run()
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

// etapeDansLeCadre prépare un formulaire pour le cadre de l'hôte.
func etapeDansLeCadre(form *huh.Form, ancre huh.Field) *etapeModel {
	// L'hôte traduit ces deux commandes en fin d'écran : tea.Quit ne ferme
	// que le formulaire, pas tout le programme.
	form.SubmitCmd = tea.Quit
	form.CancelCmd = tea.Interrupt
	// La barre du bas de l'hôte annonce déjà les touches (Touches) : l'aide
	// de huh les répéterait, et sa ligne, jamais coupée, déborderait d'un
	// cadre étroit.
	m := newEtapeModel(form.WithShowHelp(false), ancre)
	m.dansLeCadre = true
	return m
}

// lancerEtapeDansLeCadre confie le formulaire à l'hôte au lieu de lancer un
// programme. Le modèle est lu directement, pas celui que rend afficher : sur
// Ctrl+C, ce dernier peut être nul.
func lancerEtapeDansLeCadre(h *hote, form *huh.Form, ancre huh.Field) error {
	m := etapeDansLeCadre(form, ancre)
	if _, err := h.afficher(m); err != nil {
		return err
	}
	if m.retour {
		return errRetour
	}
	if form.State == huh.StateAborted {
		return huh.ErrUserAborted
	}
	return nil
}

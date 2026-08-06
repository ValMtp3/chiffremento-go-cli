package main

import (
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Direction artistique : monospace, dense, un seul accent.
//
// Contrainte de départ : rendu identique sur tous les terminaux. On s'interdit
// donc les emoji, les Nerd Fonts et les ligatures, et on se limite au
// box-drawing simple ligne présent dans toutes les polices mono. Seule la
// fidélité de la teinte se dégrade sur les terminaux limités : CompleteColor
// fournit explicitement les trois variantes, la mise en page ne bouge pas.
var (
	// Accent unique. #E65A28 en truecolor, 166 en 256 couleurs, rouge vif en 16.
	accent = lipgloss.CompleteColor{TrueColor: "#E65A28", ANSI256: "166", ANSI: "9"}

	// Trois niveaux de gris, rien de plus.
	textColor  = lipgloss.CompleteColor{TrueColor: "#D8D8D8", ANSI256: "252", ANSI: "7"}
	dimColor   = lipgloss.CompleteColor{TrueColor: "#8C8C8C", ANSI256: "245", ANSI: "7"}
	faintColor = lipgloss.CompleteColor{TrueColor: "#5A5A5A", ANSI256: "240", ANSI: "8"}
)

var (
	styleAccent = lipgloss.NewStyle().Foreground(accent)
	styleText   = lipgloss.NewStyle().Foreground(textColor)
	styleDim    = lipgloss.NewStyle().Foreground(dimColor)
	styleFaint  = lipgloss.NewStyle().Foreground(faintColor)

	// styleLabel aligne la colonne de gauche : toutes les valeurs commencent
	// donc exactement au même endroit.
	styleLabel = lipgloss.NewStyle().Foreground(dimColor).Width(labelWidth)

	styleBox = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(faintColor).
			Padding(0, 2)

	styleError = lipgloss.NewStyle().Foreground(accent).Bold(true)
)

// Largeurs fixes : c'est ce qui rend l'affichage rigoureusement identique
// d'un terminal à l'autre. contentWidth inclut le padding (convention
// lipgloss), innerWidth est la place réellement disponible pour du texte.
const (
	contentWidth = 52
	innerWidth   = contentWidth - 4
	labelWidth   = 10
)

// formTheme applique la DA aux formulaires huh.
func formTheme() *huh.Theme {
	t := huh.ThemeBase()

	t.Focused.Base = t.Focused.Base.BorderForeground(accent)
	t.Focused.Title = t.Focused.Title.Foreground(accent)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(accent)
	t.Focused.Description = t.Focused.Description.Foreground(dimColor)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(accent).SetString("> ")
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(accent)
	t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(textColor)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(accent).SetString("> ")
	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(accent)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(faintColor)
	t.Focused.TextInput.Text = t.Focused.TextInput.Text.Foreground(textColor)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(accent)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(accent).SetString(" !")
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(lipgloss.Color("0")).Background(accent)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(dimColor)

	t.Blurred.Base = t.Blurred.Base.BorderForeground(faintColor)
	t.Blurred.Title = t.Blurred.Title.Foreground(dimColor)
	t.Blurred.Description = t.Blurred.Description.Foreground(faintColor)
	t.Blurred.TextInput.Prompt = t.Blurred.TextInput.Prompt.Foreground(faintColor).SetString("  ")
	t.Blurred.SelectSelector = t.Blurred.SelectSelector.SetString("  ")

	t.Help.ShortKey = t.Help.ShortKey.Foreground(dimColor)
	t.Help.ShortDesc = t.Help.ShortDesc.Foreground(faintColor)
	t.Help.ShortSeparator = t.Help.ShortSeparator.Foreground(faintColor)

	return t
}

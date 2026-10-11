package main

import (
	"testing"

	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// TestCollerLeMotDePasseAuDechiffrement : une phrase copiée (gestionnaire de
// mots de passe, écran de la phrase générée) doit pouvoir se coller dans le
// champ du déchiffrement. Un terminal transmet un collage comme un bloc de
// caractères marqué Paste ; le champ doit le prendre tel quel.
func TestCollerLeMotDePasseAuDechiffrement(t *testing.T) {
	p, err := pkg.GenererPhrase(pkg.DefautMotsPhrase)
	if err != nil {
		t.Fatal(err)
	}
	password := ""
	form, ancre := passwordForm("format v4 · aes-256-gcm", &password)
	m := ouvrirEtape(t, form, ancre)
	envoyerEtape(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(p.Texte), Paste: true})
	envoyerEtape(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.form.State != huh.StateCompleted {
		t.Fatal("le formulaire n'a pas accepté le mot de passe collé")
	}
	if password != p.Texte {
		t.Errorf("collé %q, reçu %q", p.Texte, password)
	}
}

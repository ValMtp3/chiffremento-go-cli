package main

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"chiffremento-cli/pkg"
)

// ouvrirEtape monte un écran comme le ferait lancerEtape, sans terminal.
func ouvrirEtape(t *testing.T, form *huh.Form, ancre huh.Field) *etapeModel {
	t.Helper()
	m := newEtapeModel(form, ancre)
	derouleEtape(t, m, m.Init(), 0)
	// Sans taille de fenêtre, huh laisse les listes à une seule ligne visible :
	// le test verrait un écran que personne n'a jamais sous les yeux.
	envoyerEtape(t, m, tea.WindowSizeMsg{Width: 100, Height: 40})
	return m
}

func envoyerEtape(t *testing.T, m *etapeModel, msg tea.Msg) {
	t.Helper()
	_, cmd := m.Update(msg)
	derouleEtape(t, m, cmd, 0)
}

// derouleEtape exécute une commande et réinjecte le message produit, comme la
// boucle de Bubble Tea. La profondeur est bornée : une commande qui se
// relancerait indéfiniment ferait tourner le test sans fin plutôt qu'échouer.
func derouleEtape(t *testing.T, m *etapeModel, cmd tea.Cmd, profondeur int) {
	t.Helper()
	if cmd == nil || profondeur > 40 {
		return
	}
	msg := cmd()
	if msg == nil {
		return
	}
	if _, quitte := msg.(tea.QuitMsg); quitte {
		return
	}
	// tea.Batch et tea.Sequence portent tous deux une liste de commandes, mais
	// le second le fait dans un type non exporté : impossible de l'écrire dans
	// un `case`. Or c'est celui que renvoie Form.Init, et sans lui le premier
	// champ ne prendrait jamais le focus — le test ne verrait pas ce que voit
	// l'utilisateur. On reconnaît donc les deux à leur forme.
	if v := reflect.ValueOf(msg); v.Kind() == reflect.Slice && v.Type().Elem() == reflect.TypeOf(tea.Cmd(nil)) {
		for i := range v.Len() {
			derouleEtape(t, m, v.Index(i).Interface().(tea.Cmd), profondeur+1)
		}
		return
	}
	_, suivante := m.Update(msg)
	derouleEtape(t, m, suivante, profondeur+1)
}

func touche(s string) tea.KeyMsg {
	switch s {
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	default:
		return tea.KeyMsg{Type: tea.KeyEnter}
	}
}

// TestFormKeyMapFleches : dans une liste, ← revient et → valide. C'est la
// grammaire de l'explorateur, appliquée aux décisions.
func TestFormKeyMapFleches(t *testing.T) {
	k := formKeyMap()

	if !slices.Contains(k.Select.Prev.Keys(), "left") {
		t.Errorf("← ne revient pas en arrière dans une liste: %v", k.Select.Prev.Keys())
	}
	if !slices.Contains(k.Select.Next.Keys(), "right") {
		t.Errorf("→ ne valide pas dans une liste: %v", k.Select.Next.Keys())
	}
	// Entrée doit continuer de fonctionner : c'est le réflexe de tout le monde.
	if !slices.Contains(k.Select.Next.Keys(), "enter") {
		t.Errorf("entrée ne valide plus dans une liste: %v", k.Select.Next.Keys())
	}
	// Le filtre capterait ← pour son propre curseur : la touche de retour
	// cesserait de reculer sans que rien ne l'explique. Le désactiver ne
	// suffirait pas — huh le réactive quand le champ reprend le focus — il faut
	// lui retirer sa touche.
	if len(k.Select.Filter.Keys()) > 0 {
		t.Errorf("le filtre des listes est atteignable, il prendra ← à son curseur: %v", k.Select.Filter.Keys())
	}
	// Dans un champ texte, ← appartient au curseur.
	if slices.Contains(k.Input.Prev.Keys(), "left") {
		t.Errorf("← quitte un champ texte au lieu de déplacer le curseur: %v", k.Input.Prev.Keys())
	}
}

// TestRetourDepuis : la touche de retour dépend de ce que ← fait déjà sur
// l'écran — rien dans une liste, tout dans une saisie ou l'explorateur.
func TestRetourDepuis(t *testing.T) {
	liste := huh.NewSelect[bool]().Options(huh.NewOption("oui", true))
	touches, rappel := retourDepuis(liste)
	if !slices.Contains(touches, "left") {
		t.Errorf("on ne revient pas d'une liste avec ←: %v", touches)
	}
	if !strings.Contains(rappel, "←") {
		t.Errorf("le rappel d'une liste ne montre pas ←: %q", rappel)
	}

	for nom, champ := range map[string]huh.Field{
		"saisie":      huh.NewInput(),
		"explorateur": huh.NewFilePicker(),
	} {
		touches, rappel := retourDepuis(champ)
		if slices.Contains(touches, "left") {
			t.Errorf("%s : ← est détourné du curseur ou de la navigation: %v", nom, touches)
		}
		if !slices.Contains(touches, "shift+tab") {
			t.Errorf("%s : aucun moyen de revenir en arrière: %v", nom, touches)
		}
		if !strings.Contains(rappel, "shift+tab") {
			t.Errorf("%s : le rappel n'annonce pas la bonne touche: %q", nom, rappel)
		}
	}
}

// TestRetourDepuisUneListe est le cœur de la fonctionnalité : sur la première
// question d'un écran, ← rend la main à l'écran précédent. huh y désactive sa
// propre touche « précédent », faute d'un champ où aller.
func TestRetourDepuisUneListe(t *testing.T) {
	o := optionsChiffrement{}
	form, ancre := encryptForm(&o, false, -1)
	m := ouvrirEtape(t, form, ancre)

	if m.form.GetFocusedField() != ancre {
		t.Fatal("l'écran ne s'ouvre pas sur sa première question")
	}
	envoyerEtape(t, m, touche("left"))
	if !m.retour {
		t.Error("← sur la première question ne revient pas à l'écran précédent")
	}
}

// TestPasDeRetourDepuisLesQuestionsSuivantes : ailleurs qu'à la première
// question, ← reste la navigation interne de huh — il remonte d'un champ, il ne
// quitte pas l'écran.
func TestPasDeRetourDepuisLesQuestionsSuivantes(t *testing.T) {
	o := optionsChiffrement{}
	form, ancre := encryptForm(&o, false, -1)
	m := ouvrirEtape(t, form, ancre)

	envoyerEtape(t, m, touche("enter")) // l'algorithme est choisi
	if m.form.GetFocusedField() == ancre {
		t.Fatal("le formulaire n'a pas avancé à la question suivante")
	}

	envoyerEtape(t, m, touche("left"))
	if m.retour {
		t.Error("← a quitté l'écran alors qu'il restait une question au-dessus")
	}
	if m.form.GetFocusedField() != ancre {
		t.Error("← n'est pas remonté à la question précédente")
	}
}

// TestRetourDepuisUneSaisie : sur un champ texte, ← appartient au curseur, donc
// le retour passe par shift+tab — et l'écran le dit.
func TestRetourDepuisUneSaisie(t *testing.T) {
	path := ""
	form, ancre := cibleForm("enc", "saisie", &path)
	m := ouvrirEtape(t, form, ancre)

	envoyerEtape(t, m, touche("left"))
	if m.retour {
		t.Error("← quitte l'écran alors qu'il devrait déplacer le curseur")
	}

	envoyerEtape(t, m, touche("shift+tab"))
	if !m.retour {
		t.Error("shift+tab ne revient pas à l'écran précédent depuis une saisie")
	}
	if vue := m.View(); !strings.Contains(vue, "revenir à l'étape précédente") {
		t.Errorf("l'écran n'annonce pas comment revenir:\n%s", vue)
	}
}

// TestRetourDepuisLexplorateur : ← y remonte d'un dossier, la garde du mode
// « parcourir ». Le retour à l'écran précédent ne doit pas le lui prendre.
func TestRetourDepuisLexplorateur(t *testing.T) {
	path := ""
	form, ancre := cibleForm("enc", "parcourir", &path)
	m := ouvrirEtape(t, form, ancre)

	envoyerEtape(t, m, touche("left"))
	if m.retour {
		t.Error("← quitte l'explorateur au lieu de remonter d'un dossier")
	}
	envoyerEtape(t, m, touche("shift+tab"))
	if !m.retour {
		t.Error("shift+tab ne revient pas à l'écran précédent depuis l'explorateur")
	}
}

// TestEcranMotDePasseRevientEnArriere : la note qui décrit le fichier n'est pas
// sélectionnable, huh la saute. L'ancre du retour est donc la saisie, et c'est
// bien elle qui a le focus à l'ouverture.
func TestEcranMotDePasseRevientEnArriere(t *testing.T) {
	password := ""
	form, ancre := passwordForm("format v3 · aes-256-gcm", &password)
	m := ouvrirEtape(t, form, ancre)

	if m.form.GetFocusedField() != ancre {
		t.Fatal("l'écran ne s'ouvre pas sur la saisie du mot de passe")
	}
	envoyerEtape(t, m, touche("shift+tab"))
	if !m.retour {
		t.Error("shift+tab ne revient pas au choix de la cible")
	}
}

// TestListeOuverteSurToutesSesReponses garde le piège de huh décrit par
// reponseAccessor : une liste dont la valeur n'est pas la première option
// s'ouvre défilée d'autant de crans, et les réponses du dessus disparaissent.
// Le cas arrive à chaque retour en arrière, puisque l'écran rouvre sur les
// réponses déjà données.
func TestListeOuverteSurToutesSesReponses(t *testing.T) {
	valeur := false
	champ := ouiNon("compresser", "réduit la taille", &valeur)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	if vue := ouvrirEtape(t, form, champ).View(); !strings.Contains(vue, "oui") {
		t.Errorf("réponse « non » retenue : la réponse « oui » n'est plus visible:\n%s", vue)
	}

	// Le même piège sur une liste de trois options, telle qu'elle rouvre après
	// un aller-retour depuis la confirmation d'écrasement.
	o := optionsChiffrement{algo: pkg.AlgoCascade, kdf: pkg.KDFMaximum}
	formEnc, ancre := encryptForm(&o, false, -1)
	vue := ouvrirEtape(t, formEnc, ancre).View()
	for _, attendu := range []string{"aes-256-gcm", "cascade"} {
		if !strings.Contains(vue, attendu) {
			t.Errorf("l'option %q manque à l'ouverture:\n%s", attendu, vue)
		}
	}
}

// TestOuiNonEstUneListe : les questions fermées sont des listes verticales, et
// non deux boutons côte à côte — sinon ←/→ y basculeraient la réponse au lieu
// de naviguer dans le parcours.
func TestOuiNonEstUneListe(t *testing.T) {
	valeur := false
	champ := ouiNon("compresser", "réduit la taille", &valeur)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	m := ouvrirEtape(t, form, champ)

	vue := m.View()
	if !strings.Contains(vue, "oui") || !strings.Contains(vue, "non") {
		t.Errorf("les deux réponses ne sont pas proposées:\n%s", vue)
	}

	envoyerEtape(t, m, touche("left"))
	if valeur {
		t.Error("← a basculé la réponse au lieu de revenir en arrière")
	}
	if !m.retour {
		t.Error("← ne revient pas à l'écran précédent")
	}

	envoyerEtape(t, m, touche("up"))
	if !valeur {
		t.Error("↑ ne change pas la réponse")
	}
}

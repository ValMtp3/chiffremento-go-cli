package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

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
	// Le curseur d'un champ texte clignote en se réarmant lui-même : sa commande
	// dort une demi-seconde puis rend un BlinkMsg qui en programme un autre. La
	// dérouler jusqu'à la profondeur maximale coûtait vingt secondes par test sur
	// un écran de saisie, pour une animation qu'aucun test ne regarde.
	if reflect.TypeOf(msg).Name() == "BlinkMsg" {
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

// TestOptionsSurviventAuRetour : un « ← » de trop sur la première question de
// l'écran des options renvoie au choix de la cible, et l'écran est réaffiché
// ensuite. Les réponses déjà données doivent s'y retrouver — c'est ce que
// promet la grammaire de navigation, et ce que les options perdaient quand
// elles étaient déclarées dans tuiEncrypt plutôt que dans runTUI.
func TestOptionsSurviventAuRetour(t *testing.T) {
	saisi := optionsChiffrement{
		algo:       pkg.AlgoChaCha,
		kdf:        pkg.KDFMaximum,
		pad:        true,
		padNiveau:  pkg.PadFort,
		garderMeta: true,
		brouiller:  true,
		password:   "phrase de passe déjà tapée",
		confirm:    "phrase de passe déjà tapée",
	}
	o := saisi

	// Le réaffichage de l'écran repasse par appliquerDefauts.
	appliquerDefauts(&o, false)

	if o != saisi {
		t.Errorf("les réponses ont été réinitialisées au retour :\n  avant %+v\n  après %+v", saisi, o)
	}
}

// TestOptionsNeuvesPrennentLesDefauts : à l'inverse, une cible qu'on aborde
// pour la première fois part des valeurs par défaut — et la compression suit le
// fait que ce soit un dossier, où le tar et les métadonnées répétitives la
// rendent nettement plus payante.
func TestOptionsNeuvesPrennentLesDefauts(t *testing.T) {
	for _, cas := range []struct {
		nom        string
		estDossier bool
	}{
		{"fichier", false},
		{"dossier", true},
	} {
		t.Run(cas.nom, func(t *testing.T) {
			var o optionsChiffrement
			appliquerDefauts(&o, cas.estDossier)

			if o.algo != pkg.AlgoAES {
				t.Errorf("algorithme par défaut = %d, attendu AES (%d)", o.algo, pkg.AlgoAES)
			}
			if o.kdf != pkg.KDFStandard {
				t.Errorf("profil KDF par défaut = %q, attendu %q", o.kdf, pkg.KDFStandard)
			}
			if o.padNiveau != pkg.PadStandard {
				t.Errorf("palier par défaut = %q, attendu %q", o.padNiveau, pkg.PadStandard)
			}
			if o.compresser != cas.estDossier {
				t.Errorf("compression par défaut = %v, attendu %v", o.compresser, cas.estDossier)
			}
		})
	}
}

// TestFlecheDroiteValideLeDernierChamp : la grammaire annoncée est « → valide »
// partout. huh désactive pourtant Next sur le dernier champ d'un écran et n'y
// laisse que Submit : → n'y déclenchait donc rien du tout.
//
// Le cas se voyait sur le premier écran, dont le dernier champ est le choix de
// la cible : valider « parcourir les fichiers » avec → ne faisait rien, et
// l'explorateur restait inaccessible à qui n'essayait pas entrée.
func TestFlecheDroiteValideLeDernierChamp(t *testing.T) {
	action, mode := "enc", "saisie"
	form := choixForm(&action, &mode, true)
	m := ouvrirEtape(t, form, nil)

	envoyerEtape(t, m, touche("right")) // valide l'opération, descend à la cible
	envoyerEtape(t, m, touche("down"))  // « parcourir les fichiers »
	envoyerEtape(t, m, touche("right")) // doit soumettre l'écran

	if m.form.State != huh.StateCompleted {
		t.Error("→ ne valide pas le dernier champ de l'écran : l'écran suivant ne s'ouvrira jamais")
	}
	if mode != "parcourir" {
		t.Errorf("mode retenu = %q, attendu « parcourir »", mode)
	}
}

// TestFlecheDroiteValideUneQuestionUnique : même cause, portée plus large. Un
// écran qui ne pose qu'une question n'a qu'un champ, donc son unique champ est
// le dernier — l'écrasement, la restitution du nom, la suppression après coup et
// le brouillage sont tous dans ce cas.
func TestFlecheDroiteValideUneQuestionUnique(t *testing.T) {
	var reponse bool
	champ := questionFermee("supprimer l'original ?", "il vient d'être chiffré",
		"supprimer", "garder", &reponse)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	m := ouvrirEtape(t, form, champ)

	envoyerEtape(t, m, touche("right"))

	if m.form.State != huh.StateCompleted {
		t.Error("→ ne valide pas une question fermée isolée")
	}
}

// TestEntreeValideAussiLeDernierChamp : le correctif ajoute → sans retirer
// entrée, qui reste la touche de validation universelle.
func TestEntreeValideAussiLeDernierChamp(t *testing.T) {
	var reponse bool
	champ := questionFermee("supprimer l'original ?", "il vient d'être chiffré",
		"supprimer", "garder", &reponse)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	m := ouvrirEtape(t, form, champ)

	envoyerEtape(t, m, touche("enter"))

	if m.form.State != huh.StateCompleted {
		t.Error("entrée ne valide plus une question fermée isolée")
	}
}

// TestFlecheDroiteNeSoumetPasTropTot garde le revers du correctif précédent :
// puisque Submit porte désormais les mêmes touches que Next, → ne doit pas
// sauter par-dessus les questions restantes. huh s'en charge en n'activant
// jamais les deux à la fois, et ce test le vérifie plutôt que de le supposer.
func TestFlecheDroiteNeSoumetPasTropTot(t *testing.T) {
	action, mode := "enc", "saisie"
	form := choixForm(&action, &mode, true)
	m := ouvrirEtape(t, form, nil)

	envoyerEtape(t, m, touche("right")) // valide l'opération seulement

	if m.form.State == huh.StateCompleted {
		t.Fatal("→ a soumis l'écran entier alors que le choix de la cible restait à faire")
	}
	// Le focus doit être descendu sur la seconde question, dont la valeur par
	// défaut est encore celle d'origine.
	if mode != "saisie" {
		t.Errorf("mode = %q avant d'avoir été choisi", mode)
	}
	envoyerEtape(t, m, touche("down"))
	envoyerEtape(t, m, touche("right"))
	if m.form.State != huh.StateCompleted {
		t.Error("le second → ne soumet pas l'écran")
	}
	if mode != "parcourir" {
		t.Errorf("mode retenu = %q, attendu « parcourir »", mode)
	}
}

// --- Formulaires dans le cadre de l'écran hôte ---------------------------

// hoteSynchrone construit un hôte dont les messages venus du parcours
// arrivent dans une boîte : le test joue la boucle de Bubble Tea, une demande
// après l'autre, sans programme ni minuterie. Il devient l'hôte courant le
// temps du test.
func hoteSynchrone(t *testing.T, largeur, hauteur int) (*hote, chan tea.Msg) {
	t.Helper()
	boite := make(chan tea.Msg, 8)
	h := nouvelHote(func(msg tea.Msg) { boite <- msg })
	// Un vrai tea.Tick de cinq minutes bloquerait derouleHote d'autant.
	h.minuterie = minuterieInerte
	envoyerHote(t, h, tea.WindowSizeMsg{Width: largeur, Height: hauteur})
	hoteCourant = h
	t.Cleanup(func() { hoteCourant = nil })
	return h, boite
}

// delaiTest borne chaque attente : un relais bloqué fait échouer le test au
// lieu de le faire pendre jusqu'au délai global de go test.
const delaiTest = 10 * time.Second

// demandeRecue attend la prochaine demande d'écran du parcours et l'ouvre.
func demandeRecue(t *testing.T, h *hote, boite chan tea.Msg) {
	t.Helper()
	select {
	case msg := <-boite:
		d, ok := msg.(demandeEcran)
		if !ok {
			t.Fatalf("message reçu %T, attendu une demande d'écran", msg)
		}
		envoyerHote(t, h, d)
	case <-time.After(delaiTest):
		t.Fatal("le parcours n'a demandé aucun écran à l'hôte")
	}
}

// issueRecue attend la fin d'un parcours lancé dans une goroutine.
func issueRecue(t *testing.T, issue chan error) error {
	t.Helper()
	select {
	case err := <-issue:
		return err
	case <-time.After(delaiTest):
		t.Fatal("le parcours n'a pas rendu la main")
		return nil
	}
}

// TestLancerEtapeParLHote : avec un hôte, lancerEtape affiche le formulaire
// dans le cadre, sans programme à lui, et garde ses trois issues — retour,
// validation, abandon — plus Échap, qui revient au menu.
func TestLancerEtapeParLHote(t *testing.T) {
	cas := []struct {
		nom     string
		touche  tea.KeyMsg
		attendu error
	}{
		{"← depuis l'ancre", touche("left"), errRetour},
		{"→ valide", touche("right"), nil},
		{"échap", tea.KeyMsg{Type: tea.KeyEsc}, errMenu},
		{"ctrl+c", tea.KeyMsg{Type: tea.KeyCtrlC}, huh.ErrUserAborted},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			h, boite := hoteSynchrone(t, 100, 30)
			valeur := "b"
			champ := huh.NewSelect[string]().Title("choix").
				Options(huh.NewOption("a", "a"), huh.NewOption("b", "b")).Value(&valeur)
			form := huh.NewForm(huh.NewGroup(champ)).WithKeyMap(formKeyMap())

			issue := make(chan error, 1)
			go func() { issue <- lancerEtape(form, champ) }()
			demandeRecue(t, h, boite)
			if !strings.Contains(h.View(), "choix") {
				t.Fatalf("le formulaire n'est pas dans le cadre :\n%s", h.View())
			}
			envoyerHote(t, h, c.touche)
			if err := issueRecue(t, issue); !errors.Is(err, c.attendu) || (c.attendu == nil && err != nil) {
				t.Fatalf("lancerEtape = %v, attendu %v", err, c.attendu)
			}
			if c.attendu == nil && valeur != "b" {
				t.Errorf("valeur retenue = %q, attendu « b »", valeur)
			}
		})
	}
}

// TestLancerEtapeSansHote : sans hôte, le chemin d'avant est inchangé. Le
// seul observable sans terminal est TERM=dumb (huh en mode accessible) : il
// passe avant l'hôte, même s'il y en a un, et ne lui envoie rien.
func TestLancerEtapeSansHote(t *testing.T) {
	t.Setenv("TERM", "dumb")
	h := nouvelHote(func(msg tea.Msg) { t.Errorf("l'hôte a reçu %T en TERM=dumb", msg) })
	hoteCourant = h
	t.Cleanup(func() { hoteCourant = nil })

	valeur := ""
	champ := huh.NewSelect[string]().Title("choix").
		Options(huh.NewOption("a", "a"), huh.NewOption("b", "b")).Value(&valeur)
	// NewForm lit TERM à la construction : le formulaire naît accessible.
	form := huh.NewForm(huh.NewGroup(champ)).
		WithInput(strings.NewReader("2\n")).WithOutput(io.Discard)
	if err := lancerEtape(form, champ); err != nil {
		t.Fatalf("lancerEtape en TERM=dumb = %v", err)
	}
	if valeur != "b" {
		t.Errorf("valeur = %q, attendu « b »", valeur)
	}
}

// TestPointDInterrogationDansLeMotDePasse : ? tapé dans le champ du mot de
// passe y atterrit, au lieu d'ouvrir l'aide de l'hôte.
func TestPointDInterrogationDansLeMotDePasse(t *testing.T) {
	password := ""
	form, ancre := passwordForm("détails", &password)
	h := hoteDeTest(t, 100, 30)
	demande := montrer(t, h, etapeDansLeCadre(form, ancre))

	taper(t, h, "a?b")
	if got := ancre.GetValue(); got != "a?b" {
		t.Fatalf("saisie = %q, attendu « a?b » : ? a été pris par l'hôte", got)
	}
	if strings.Contains(h.View(), "raccourcis") {
		t.Error("l'aide s'est ouverte pendant la saisie du mot de passe")
	}
	if r, recue := reponseRecue(t, demande); recue {
		t.Errorf("l'écran s'est terminé pendant la saisie : %+v", r)
	}
}

// TestEchapRemonteDansLExplorateur : dans l'explorateur, Échap remonte d'un
// dossier, comme ←, au lieu de ramener au menu.
func TestEchapRemonteDansLExplorateur(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sous_dossier"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sous_dossier", "dedans.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a_la_racine.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	path := ""
	form, ancre := cibleForm("enc", "parcourir", &path)
	h := hoteDeTest(t, 100, 40)
	demande := montrer(t, h, etapeDansLeCadre(form, ancre))
	envoyerHote(t, h, touche("right"))
	if !strings.Contains(h.View(), "dedans.txt") {
		t.Fatalf("→ n'entre pas dans le dossier :\n%s", h.View())
	}

	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
	if r, recue := reponseRecue(t, demande); recue {
		t.Fatalf("Échap a quitté l'explorateur : %+v", r)
	}
	if !strings.Contains(h.View(), "a_la_racine.txt") {
		t.Errorf("Échap ne remonte pas d'un dossier :\n%s", h.View())
	}
}

// TestRedimensionnementDUnFormulaire : un formulaire de l'interface suit la
// largeur du cadre quand la fenêtre change, sans perdre saisie ni focus.
// huh ignore les tailles suivantes dès qu'une largeur lui a été imposée :
// etapeModel doit la lui redonner à chaque changement.
func TestRedimensionnementDUnFormulaire(t *testing.T) {
	path := ""
	form, ancre := cibleForm("enc", "saisie", &path)
	m := etapeDansLeCadre(form, ancre)
	h := hoteDeTest(t, 100, 30)
	montrer(t, h, m)
	taper(t, h, "abc")

	for _, largeur := range []int{60, 100, 56} {
		envoyerHote(t, h, tea.WindowSizeMsg{Width: largeur, Height: 24})
		interieur, _ := tailleInterieure(largeur, 24)
		for _, ligne := range strings.Split(m.View(), "\n") {
			if w := lipgloss.Width(ligne); w > interieur {
				t.Errorf("largeur %d : ligne du formulaire de %d colonnes > %d : %q", largeur, w, interieur, ligne)
			}
		}
		for _, ligne := range strings.Split(h.View(), "\n") {
			if w := lipgloss.Width(ligne); w > largeur {
				t.Errorf("largeur %d : ligne de l'écran de %d colonnes : %q", largeur, w, ligne)
			}
		}
	}
	if form.GetFocusedField() != ancre {
		t.Fatal("le focus a quitté le champ après les redimensionnements")
	}
	taper(t, h, "d")
	if got := ancre.GetValue(); got != "abcd" {
		t.Fatalf("saisie = %q, attendu « abcd »", got)
	}
}

// TestTouchesDeLEtape : la barre du bas annonce les touches du champ qui a le
// focus, et le retour seulement là où il existe.
func TestTouchesDeLEtape(t *testing.T) {
	password := ""
	form, ancre := passwordForm("détails", &password)
	m := ouvrirEtape(t, form, ancre)
	if got := m.Touches(); !strings.Contains(got, "⏎ valider") || !strings.Contains(got, "shift+tab revenir") {
		t.Errorf("touches d'une saisie = %q", got)
	}
	if !m.saisitDuTexte() || m.gardeEchap() {
		t.Errorf("saisie : saisitDuTexte %v, gardeEchap %v", m.saisitDuTexte(), m.gardeEchap())
	}

	action, mode := "enc", "saisie"
	m = ouvrirEtape(t, choixForm(&action, &mode, true), nil)
	if got := m.Touches(); !strings.Contains(got, "↑↓ choisir") || strings.Contains(got, "revenir") {
		t.Errorf("touches du premier écran = %q : rien derrière lui, pas de retour", got)
	}
	if m.saisitDuTexte() || m.gardeEchap() {
		t.Errorf("liste : saisitDuTexte %v, gardeEchap %v", m.saisitDuTexte(), m.gardeEchap())
	}
	envoyerEtape(t, m, touche("right"))
	if got := m.Touches(); !strings.Contains(got, "← revenir") {
		t.Errorf("touches de la deuxième question = %q : ← y revient à la première", got)
	}
}

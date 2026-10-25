package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// ecranDeTest donne à n'importe quel modèle ce qu'il faut pour être un
// sous-écran : un titre, ses touches, et éventuellement les touches qu'il garde
// pour lui (saisie de texte, Échap).
type ecranDeTest struct {
	modele  tea.Model
	titre   string
	touches string
	saisie  bool
	echap   bool
}

func (e *ecranDeTest) Init() tea.Cmd { return e.modele.Init() }

func (e *ecranDeTest) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, cmd := e.modele.Update(msg)
	e.modele = m
	return e, cmd
}

func (e *ecranDeTest) View() string        { return e.modele.View() }
func (e *ecranDeTest) Titre() string       { return e.titre }
func (e *ecranDeTest) Touches() string     { return e.touches }
func (e *ecranDeTest) saisitDuTexte() bool { return e.saisie }
func (e *ecranDeTest) gardeEchap() bool    { return e.echap }

// texteFixe est un modèle qui n'affiche qu'un texte et ne réagit à rien.
type texteFixe struct{ texte string }

func (m texteFixe) Init() tea.Cmd                       { return nil }
func (m texteFixe) Update(tea.Msg) (tea.Model, tea.Cmd) { return m, nil }
func (m texteFixe) View() string                        { return m.texte }

// seFermeTout de suite se termine dès son ouverture, comme un formulaire
// validé : c'est le cas le plus serré pour le relais.
type seFermeToutDeSuite struct{ numero int }

func (m seFermeToutDeSuite) Init() tea.Cmd                       { return tea.Quit }
func (m seFermeToutDeSuite) Update(tea.Msg) (tea.Model, tea.Cmd) { return m, nil }
func (m seFermeToutDeSuite) View() string                        { return fmt.Sprintf("écran %d", m.numero) }

// hoteDeTest construit un hôte sans programme ni terminal, à la taille donnée.
func hoteDeTest(t *testing.T, largeur, hauteur int) *hote {
	t.Helper()
	h := nouvelHote(func(tea.Msg) {})
	// Un vrai tea.Tick de cinq minutes bloquerait derouleHote d'autant.
	h.minuterie = minuterieInerte
	envoyerHote(t, h, tea.WindowSizeMsg{Width: largeur, Height: hauteur})
	return h
}

// minuterieInerte ne programme rien : les tests qui regardent le minuteur
// d'oubli posent la leur (minuterieDeTest, session_test.go).
func minuterieInerte(time.Duration) tea.Cmd { return nil }

// montrer remet un sous-écran à l'hôte comme le ferait afficher, sans passer
// par un programme, et rend la demande pour lire sa réponse.
func montrer(t *testing.T, h *hote, ecran sousEcran) demandeEcran {
	t.Helper()
	demande := nouvelleDemande(ecran)
	envoyerHote(t, h, demande)
	return demande
}

func envoyerHote(t *testing.T, h *hote, msg tea.Msg) {
	t.Helper()
	_, cmd := h.Update(msg)
	derouleHote(t, h, cmd, 0)
}

// derouleHote joue le rôle de la boucle de Bubble Tea : exécute la commande,
// réinjecte son message. Même garde-fous que derouleEtape (navigation_test.go).
func derouleHote(t *testing.T, h *hote, cmd tea.Cmd, profondeur int) {
	t.Helper()
	if cmd == nil || profondeur > 40 {
		return
	}
	msg := cmd()
	if msg == nil {
		return
	}
	interieur := msg
	if m, ok := msg.(messageEcran); ok {
		interieur = m.msg
	}
	// Le clignotement du curseur se réarme sans fin : aucun test ne le regarde.
	if reflect.TypeOf(interieur).Name() == "BlinkMsg" {
		return
	}
	switch msg.(type) {
	case tea.QuitMsg, tea.InterruptMsg:
		return
	}
	if v := reflect.ValueOf(msg); v.Kind() == reflect.Slice && v.Type().Elem() == reflect.TypeOf(tea.Cmd(nil)) {
		for i := range v.Len() {
			derouleHote(t, h, v.Index(i).Interface().(tea.Cmd), profondeur+1)
		}
		return
	}
	_, suivante := h.Update(msg)
	derouleHote(t, h, suivante, profondeur+1)
}

func taper(t *testing.T, h *hote, texte string) {
	t.Helper()
	for _, r := range texte {
		envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

// reponseRecue lit la réponse d'une demande sans jamais bloquer le test.
func reponseRecue(t *testing.T, demande demandeEcran) (resultatEcran, bool) {
	t.Helper()
	select {
	case r := <-demande.reponse:
		return r, true
	default:
		return resultatEcran{}, false
	}
}

// TestRedimensionnementGardeLaSaisie : redimensionner pendant une saisie ne
// perd ni le texte tapé ni le focus (Review Focus 1).
func TestRedimensionnementGardeLaSaisie(t *testing.T) {
	var valeur string
	champ := huh.NewInput().Title("phrase").Value(&valeur)
	autre := huh.NewInput().Title("autre")
	form := huh.NewForm(huh.NewGroup(champ, autre)).WithShowHelp(false)

	h := hoteDeTest(t, 100, 30)
	montrer(t, h, &ecranDeTest{modele: form, titre: "saisie", touches: "⏎ valider", saisie: true})
	taper(t, h, "abc")
	envoyerHote(t, h, tea.WindowSizeMsg{Width: 60, Height: 20})

	if form.GetFocusedField() != champ {
		t.Fatal("le focus a quitté le champ après le redimensionnement")
	}
	if got := champ.GetValue(); got != "abc" {
		t.Fatalf("saisie après redimensionnement = %q, attendu « abc »", got)
	}
	// Le focus est réel : la frappe suivante s'ajoute au même champ.
	taper(t, h, "d")
	if got := champ.GetValue(); got != "abcd" {
		t.Fatalf("saisie après une frappe de plus = %q, attendu « abcd »", got)
	}
	if !strings.Contains(h.View(), "abcd") {
		t.Errorf("la saisie n'est pas affichée :\n%s", h.View())
	}
	for _, ligne := range strings.Split(h.View(), "\n") {
		if w := lipgloss.Width(ligne); w > 60 {
			t.Errorf("ligne de largeur %d > 60 après redimensionnement : %q", w, ligne)
		}
	}
}

// TestAideSOuvreEtSeFerme : ? ouvre l'aide ; ?, Échap ou ⏎ la referment.
func TestAideSOuvreEtSeFerme(t *testing.T) {
	for _, fermeture := range []tea.KeyMsg{
		{Type: tea.KeyRunes, Runes: []rune{'?'}},
		{Type: tea.KeyEsc},
		{Type: tea.KeyEnter},
	} {
		t.Run(fermeture.String(), func(t *testing.T) {
			h := hoteDeTest(t, 100, 30)
			demande := montrer(t, h, &ecranDeTest{modele: texteFixe{"menu principal"}, titre: "menu"})

			taper(t, h, "?")
			if !strings.Contains(h.View(), "raccourcis") {
				t.Fatalf("? n'ouvre pas l'aide :\n%s", h.View())
			}
			if strings.Contains(h.View(), "menu principal") {
				t.Errorf("l'écran courant reste visible sous l'aide :\n%s", h.View())
			}

			envoyerHote(t, h, fermeture)
			if strings.Contains(h.View(), "raccourcis") {
				t.Fatalf("%s ne referme pas l'aide :\n%s", fermeture, h.View())
			}
			if !strings.Contains(h.View(), "menu principal") {
				t.Errorf("l'écran courant n'est pas revenu :\n%s", h.View())
			}
			// Fermer l'aide ne doit rien décider pour l'écran en dessous :
			// Échap ou ⏎ ne remontent pas jusqu'à lui.
			if r, recue := reponseRecue(t, demande); recue {
				t.Errorf("fermer l'aide a terminé l'écran courant : %+v", r)
			}
		})
	}
}

// TestPointDInterrogationDansUneSaisie : dans un champ texte, ? est un
// caractère comme un autre — une phrase de passe peut en contenir.
func TestPointDInterrogationDansUneSaisie(t *testing.T) {
	champ := huh.NewInput().Title("phrase")
	form := huh.NewForm(huh.NewGroup(champ)).WithShowHelp(false)
	h := hoteDeTest(t, 100, 30)
	montrer(t, h, &ecranDeTest{modele: form, titre: "phrase", saisie: true})

	taper(t, h, "a?b")
	if got := champ.GetValue(); got != "a?b" {
		t.Fatalf("saisie = %q, attendu « a?b » : ? a été pris par l'hôte", got)
	}
	if strings.Contains(h.View(), "raccourcis") {
		t.Error("l'aide s'est ouverte pendant une saisie")
	}
}

// TestTerminalMinuscule : en 40×10, rien ne panique ni ne déborde, aide
// ouverte ou non (Review Focus 5).
func TestTerminalMinuscule(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	long := strings.Repeat("une ligne beaucoup trop longue pour le cadre ", 5)
	corps := strings.TrimSuffix(strings.Repeat(long+"\n", 30), "\n")
	montrer(t, h, &ecranDeTest{modele: texteFixe{corps}, titre: "une étape au nom très long", touches: strings.Repeat("x choisir  ", 20)})
	envoyerHote(t, h, tea.WindowSizeMsg{Width: 40, Height: 10})

	verifier := func(etat string) {
		t.Helper()
		lignes := strings.Split(h.View(), "\n")
		if len(lignes) > 10 {
			t.Errorf("%s : %d lignes pour un terminal de 10", etat, len(lignes))
		}
		for _, ligne := range lignes {
			if w := lipgloss.Width(ligne); w > 40 {
				t.Errorf("%s : ligne de largeur %d > 40 : %q", etat, w, ligne)
			}
		}
	}
	verifier("écran courant")
	taper(t, h, "?")
	verifier("aide ouverte")
}

// TestBarres : le fil d'Ariane en haut, les touches de l'écran et les touches
// globales en bas, l'indicateur de phrase à droite quand il est actif.
func TestBarres(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	envoyerHote(t, h, operationMsg("chiffrement"))
	montrer(t, h, &ecranDeTest{modele: texteFixe{"options"}, titre: "options", touches: "↑↓ choisir  → valider"})

	lignes := strings.Split(h.View(), "\n")
	haut, bas := lignes[0], lignes[len(lignes)-1]
	if !strings.Contains(haut, "chiffremento "+version+" · chiffrement › options") {
		t.Errorf("barre du haut = %q", haut)
	}
	if strings.Contains(haut, "●") {
		t.Errorf("indicateur de phrase affiché sans phrase gardée : %q", haut)
	}
	for _, attendu := range []string{"↑↓ choisir  → valider", "? aide", "ctrl+c quitter"} {
		if !strings.Contains(bas, attendu) {
			t.Errorf("barre du bas sans %q : %q", attendu, bas)
		}
	}

	h.phrase = &phraseSession{}
	h.phrase.garder([]byte("phrase gardée"))
	envoyerHote(t, h, phraseGardeeMsg{})
	haut = strings.Split(h.View(), "\n")[0]
	if !strings.Contains(haut, "● phrase en mémoire") {
		t.Errorf("indicateur de phrase absent : %q", haut)
	}
	// Collé au bord droit du cadre : même colonne de fin que la bordure.
	if w := lipgloss.Width(haut); w != (100-80)/2+80 {
		t.Errorf("la barre du haut finit à la colonne %d, attendu %d : %q", w, (100-80)/2+80, haut)
	}
}

// TestCtrlCRendErrUserAborted : Ctrl+C termine l'écran courant par
// huh.ErrUserAborted et interrompt le programme, même aide ouverte.
func TestCtrlCRendErrUserAborted(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	demande := montrer(t, h, &ecranDeTest{modele: texteFixe{"x"}})
	taper(t, h, "?")

	_, cmd := h.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("Ctrl+C ne renvoie aucune commande")
	}
	if _, ok := cmd().(tea.InterruptMsg); !ok {
		t.Error("Ctrl+C n'interrompt pas le programme")
	}
	r, recue := reponseRecue(t, demande)
	if !recue || !errors.Is(r.err, huh.ErrUserAborted) {
		t.Fatalf("réponse = %+v (reçue : %v), attendu huh.ErrUserAborted", r, recue)
	}
	// Plus personne n'affichera rien : afficher rend la main tout de suite.
	if _, err := h.afficher(&ecranDeTest{modele: texteFixe{"y"}}); !errors.Is(err, huh.ErrUserAborted) {
		t.Errorf("afficher après Ctrl+C = %v, attendu huh.ErrUserAborted", err)
	}
}

// TestEchapRevientAuMenu : Échap termine l'écran par errMenu, sauf s'il garde
// la touche pour lui (explorateur, progression).
func TestEchapRevientAuMenu(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	demande := montrer(t, h, &ecranDeTest{modele: texteFixe{"x"}})
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
	if r, recue := reponseRecue(t, demande); !recue || !errors.Is(r.err, errMenu) {
		t.Fatalf("réponse = %+v (reçue : %v), attendu errMenu", r, recue)
	}

	demande = montrer(t, h, &ecranDeTest{modele: texteFixe{"x"}, echap: true})
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
	if r, recue := reponseRecue(t, demande); recue {
		t.Fatalf("un écran qui garde Échap a été terminé : %+v", r)
	}
}

// TestFinDeLEcranRendLeModeleFinal : un sous-écran qui se termine par
// tea.Quit rend la main sans erreur, avec son modèle final, et le programme,
// lui, continue.
func TestFinDeLEcranRendLeModeleFinal(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	ecran := &ecranDeTest{modele: seFermeToutDeSuite{numero: 7}}
	demande := montrer(t, h, ecran)
	r, recue := reponseRecue(t, demande)
	if !recue || r.err != nil {
		t.Fatalf("réponse = %+v (reçue : %v), attendu une fin sans erreur", r, recue)
	}
	if r.modele != ecran {
		t.Errorf("modèle final = %v, attendu l'écran affiché", r.modele)
	}
	if strings.Contains(h.View(), "écran 7") {
		t.Errorf("l'écran terminé reste affiché :\n%s", h.View())
	}
}

// TestMessagePerimeIgnore : un message produit par un écran déjà terminé —
// son tick d'animation, sa fin tardive — ne touche pas l'écran suivant.
func TestMessagePerimeIgnore(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	premier := montrer(t, h, &ecranDeTest{modele: texteFixe{"premier"}})
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
	if _, recue := reponseRecue(t, premier); !recue {
		t.Fatal("le premier écran ne s'est pas terminé")
	}
	idPerime := h.prochainID - 1

	second := montrer(t, h, &ecranDeTest{modele: texteFixe{"second"}})
	envoyerHote(t, h, finEcranMsg{id: idPerime})
	if r, recue := reponseRecue(t, second); recue {
		t.Fatalf("la fin d'un écran périmé a terminé le suivant : %+v", r)
	}
	if !strings.Contains(h.View(), "second") {
		t.Errorf("le second écran n'est plus affiché :\n%s", h.View())
	}
}

// TestRelaisSansCourse : 100 écrans de suite confiés depuis la goroutine d'un
// parcours à un vrai programme. go test -race y relève toute donnée partagée
// sans synchronisation.
func TestRelaisSansCourse(t *testing.T) {
	var programme *tea.Program
	h := nouvelHote(func(msg tea.Msg) { programme.Send(msg) })
	programme = tea.NewProgram(h,
		tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutSignalHandler())

	// Garde-fou : un relais bloqué ferait pendre le test jusqu'au délai global
	// de go test. On tue le programme, et l'erreur remonte ci-dessous.
	minuteur := time.AfterFunc(30*time.Second, programme.Kill)
	defer minuteur.Stop()

	erreurs := make(chan error, 1)
	go func() {
		defer programme.Quit()
		for i := range 100 {
			modele, err := h.afficher(&ecranDeTest{modele: seFermeToutDeSuite{numero: i}, titre: "relais"})
			if err != nil {
				erreurs <- fmt.Errorf("écran %d : %w", i, err)
				return
			}
			if got := modele.(*ecranDeTest).modele.(seFermeToutDeSuite).numero; got != i {
				erreurs <- fmt.Errorf("écran %d : modèle final de l'écran %d", i, got)
				return
			}
		}
		erreurs <- nil
	}()

	_, errProgramme := programme.Run()
	h.fermer()
	if err := <-erreurs; err != nil {
		t.Fatal(err)
	}
	if errProgramme != nil {
		t.Fatalf("programme : %v", errProgramme)
	}
}

// quitteEnSuite se termine par un tea.Quit placé au bout d'une tea.Sequence :
// le chemin que prend un sous-écran qui enchaîne des commandes avant de rendre
// la main.
type quitteEnSuite struct{}

func (quitteEnSuite) Init() tea.Cmd {
	rien := func() tea.Msg { return nil }
	return tea.Sequence(rien, rien, tea.Quit)
}
func (m quitteEnSuite) Update(tea.Msg) (tea.Model, tea.Cmd) { return m, nil }
func (quitteEnSuite) View() string                          { return "suite" }

// TestSuiteDeCommandesReconnue : un tea.Quit au bout d'une tea.Sequence ferme
// le sous-écran, pas tout le programme. Il faut un vrai programme : c'est lui
// qui déplie la suite, et derouleHote le ferait à sa place.
func TestSuiteDeCommandesReconnue(t *testing.T) {
	var programme *tea.Program
	h := nouvelHote(func(msg tea.Msg) { programme.Send(msg) })
	programme = tea.NewProgram(h,
		tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutSignalHandler())
	minuteur := time.AfterFunc(30*time.Second, programme.Kill)
	defer minuteur.Stop()

	erreurs := make(chan error, 1)
	go func() {
		defer programme.Quit()
		for i := range 2 {
			if _, err := h.afficher(&ecranDeTest{modele: quitteEnSuite{}}); err != nil {
				erreurs <- fmt.Errorf("écran %d : %w (la suite a fermé le programme)", i+1, err)
				return
			}
		}
		erreurs <- nil
	}()

	_, errProgramme := programme.Run()
	h.fermer()
	if err := <-erreurs; err != nil {
		t.Fatal(err)
	}
	if errProgramme != nil {
		t.Fatalf("programme : %v", errProgramme)
	}
}

// TestAideFermeeQuandLEcranChange : l'aide ouverte sur un écran ne recouvre
// pas le suivant — sinon l'utilisateur ne verrait pas qu'on lui pose une
// nouvelle question.
func TestAideFermeeQuandLEcranChange(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	montrer(t, h, &ecranDeTest{modele: texteFixe{"premier"}})
	taper(t, h, "?")
	// Le premier écran se termine par une commande, aide ouverte.
	envoyerHote(t, h, finEcranMsg{id: h.idCourant})
	if strings.Contains(h.View(), "raccourcis") {
		t.Errorf("l'aide reste ouverte après la fin de l'écran :\n%s", h.View())
	}

	// Aide ouverte sans écran, puis un écran arrive.
	taper(t, h, "?")
	montrer(t, h, &ecranDeTest{modele: texteFixe{"second"}})
	if !strings.Contains(h.View(), "second") || strings.Contains(h.View(), "raccourcis") {
		t.Errorf("l'aide recouvre le nouvel écran :\n%s", h.View())
	}
}

// programmeSansTerminal fait tourner un vrai programme Bubble Tea autour de
// l'hôte, sans terminal ni rendu : le relais par programme.Send est réel.
// L'entrée est un tube muet plutôt que rien : sans entrée donnée, Bubble Tea
// lirait l'entrée standard du processus de test.
func programmeSansTerminal(t *testing.T, h *hote) *tea.Program {
	t.Helper()
	lecture, ecriture := io.Pipe()
	t.Cleanup(func() { ecriture.Close() })
	p := tea.NewProgram(h, tea.WithInput(lecture), tea.WithOutput(io.Discard), tea.WithoutRenderer(), tea.WithoutSignalHandler())
	h.envoyer = p.Send
	return p
}

// TestSortieExterneLibereLeParcours : si le programme sort sans que le
// parcours l'ait demandé (signal, panne), le parcours bloqué dans afficher
// rend la main au lieu d'attendre une réponse qui ne viendra jamais.
func TestSortieExterneLibereLeParcours(t *testing.T) {
	h := nouvelHote(nil)
	p := programmeSansTerminal(t, h)
	issue := make(chan error, 1)
	ouvert := make(chan struct{})
	go func() {
		close(ouvert)
		_, err := h.afficher(&ecranDeTest{modele: texteFixe{"en attente"}})
		issue <- err
	}()
	fin := make(chan bool, 1)
	go func() {
		interrompu, _ := h.executer(p)
		fin <- interrompu
	}()
	<-ouvert
	time.Sleep(50 * time.Millisecond) // le temps que la demande parte
	p.Quit()
	select {
	case interrompu := <-fin:
		if !interrompu {
			t.Error("une sortie que le parcours n'a pas demandée doit compter comme une interruption")
		}
	case <-time.After(delaiTest):
		t.Fatal("executer n'a pas rendu la main")
	}
	if err := issueRecue(t, issue); !errors.Is(err, huh.ErrUserAborted) {
		t.Fatalf("afficher = %v, attendu huh.ErrUserAborted", err)
	}
}

// TestQuitterTermineLeProgramme : quitter, demandé par le parcours, termine
// le programme normalement — pas une interruption.
func TestQuitterTermineLeProgramme(t *testing.T) {
	h := nouvelHote(nil)
	p := programmeSansTerminal(t, h)
	fin := make(chan bool, 1)
	go func() {
		interrompu, err := h.executer(p)
		if err != nil {
			t.Errorf("executer = %v", err)
		}
		fin <- interrompu
	}()
	time.Sleep(50 * time.Millisecond)
	h.quitter()
	select {
	case interrompu := <-fin:
		if interrompu {
			t.Error("quitter a été pris pour une interruption")
		}
	case <-time.After(delaiTest):
		t.Fatal("quitter n'a pas terminé le programme")
	}
}

// TestPaniqueDuParcoursRendLeTerminal : une panique dans la goroutine du
// parcours ne fait plus sortir le processus terminal cassé. Elle est notée,
// rendre est appelé (comme runTUI : temporaires, phrase, puis Kill), et Run
// rend la main — c'est lui qui quitte l'écran alternatif et rend le mode du
// terminal.
func TestPaniqueDuParcoursRendLeTerminal(t *testing.T) {
	h := nouvelHote(nil)
	p := programmeSansTerminal(t, h)
	h.phrase = &phraseSession{}
	h.phrase.garder([]byte("phrase à oublier"))

	fin := make(chan bool, 1)
	go func() {
		interrompu, err := h.executer(p)
		if err != nil {
			t.Errorf("executer = %v", err)
		}
		fin <- interrompu
	}()
	var garde gardeParcours
	rendu := make(chan struct{})
	go garde.mener(func() { panic("boum") }, func() {
		h.fermer()
		p.Kill()
		close(rendu)
	})

	select {
	case interrompu := <-fin:
		if !interrompu {
			t.Error("une panique du parcours doit compter comme une interruption")
		}
	case <-time.After(delaiTest):
		t.Fatal("Run n'a pas rendu la main après la panique du parcours")
	}
	select {
	case <-rendu:
	case <-time.After(delaiTest):
		t.Fatal("rendre n'a pas été appelé")
	}
	note := garde.panique.Load()
	if note == nil || note.valeur != "boum" {
		t.Fatalf("panique notée = %+v, attendu « boum »", note)
	}
	if !strings.Contains(string(note.pile), "TestPaniqueDuParcoursRendLeTerminal") {
		t.Errorf("la pile notée ne montre pas l'origine :\n%s", note.pile)
	}
	if h.phrase.active() {
		t.Error("la phrase de session n'a pas été oubliée")
	}
}

// TestParcoursSansPaniqueNeRendRien : un parcours qui finit normalement ne
// note rien et n'appelle pas rendre.
func TestParcoursSansPaniqueNeRendRien(t *testing.T) {
	var garde gardeParcours
	appele := false
	garde.mener(func() {}, func() { appele = true })
	if appele || garde.panique.Load() != nil {
		t.Errorf("rendre appelé = %v, panique = %v", appele, garde.panique.Load())
	}
}

// TestCodeDuSignal : 129 pour SIGHUP (128 + 1), 130 pour Ctrl+C et SIGTERM.
func TestCodeDuSignal(t *testing.T) {
	cas := map[os.Signal]int{syscall.SIGHUP: exitRaccroche, os.Interrupt: exitInterrompu, syscall.SIGTERM: exitInterrompu}
	for signal, attendu := range cas {
		if got := codeDuSignal(signal); got != attendu {
			t.Errorf("codeDuSignal(%v) = %d, attendu %d", signal, got, attendu)
		}
	}
	if exitRaccroche != 129 {
		t.Errorf("exitRaccroche = %d, attendu 129", exitRaccroche)
	}
}

// TestSurRaccrochageSArrete : sans signal, arreter termine l'écoute sans
// appeler agir, et peut être appelée deux fois.
func TestSurRaccrochageSArrete(t *testing.T) {
	arreter := surRaccrochage(func() { t.Error("agir appelé sans SIGHUP") })
	arreter()
	arreter()
}

// remplacerFermerTemporaires compte les appels au lieu de fermer pour de bon
// le registre de pkg, qui resterait fermé pour les tests suivants.
func remplacerFermerTemporaires(t *testing.T) *atomic.Int32 {
	t.Helper()
	var appels atomic.Int32
	ancien := fermerTemporaires
	fermerTemporaires = func() { appels.Add(1) }
	t.Cleanup(func() { fermerTemporaires = ancien })
	return &appels
}

// TestCtrlCAttendQueLeParcoursEfface : sur Ctrl+C pendant une opération (une
// dérivation Argon2 ne s'interrompt pas), la session attend que le parcours
// ait fini et mis à zéro sa copie du mot de passe avant de rendre la main —
// main fait os.Exit juste après, et les defer du parcours ne tourneraient
// jamais.
func TestCtrlCAttendQueLeParcoursEfface(t *testing.T) {
	appels := remplacerFermerTemporaires(t)
	h := nouvelHote(nil)
	p := programmeSansTerminal(t, h)
	s := &session{}
	h.phrase = &s.phrase
	motDePasse := []byte("phrase de l'opération")
	parcours := func() {
		defer zero(motDePasse)
		if _, err := h.afficher(&ecranDeTest{modele: texteFixe{"dérivation…"}}); errors.Is(err, huh.ErrUserAborted) {
			time.Sleep(300 * time.Millisecond) // l'opération finit sa dérivation
		}
	}
	go p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})

	code, err := menerSession(h, s, p, parcours)
	if err != nil || code != exitInterrompu {
		t.Fatalf("menerSession = (%d, %v), attendu (%d, nil)", code, err, exitInterrompu)
	}
	if !toutAZero(motDePasse) {
		t.Errorf("la copie du mot de passe n'est pas à zéro au retour : %q", motDePasse)
	}
	if appels.Load() == 0 {
		t.Error("les temporaires n'ont pas été fermés")
	}
}

// TestSortieMalgreUnParcoursBloque : un parcours qui ne finit pas ne retient
// pas la sortie au-delà de delaiFinParcours.
func TestSortieMalgreUnParcoursBloque(t *testing.T) {
	remplacerFermerTemporaires(t)
	ancien := delaiFinParcours
	delaiFinParcours = 100 * time.Millisecond
	t.Cleanup(func() { delaiFinParcours = ancien })
	h := nouvelHote(nil)
	p := programmeSansTerminal(t, h)
	s := &session{}
	h.phrase = &s.phrase
	bloque := make(chan struct{})
	t.Cleanup(func() { close(bloque) })
	go p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})

	debut := time.Now()
	code, _ := menerSession(h, s, p, func() { <-bloque })
	if code != exitInterrompu {
		t.Errorf("code %d, attendu %d", code, exitInterrompu)
	}
	if duree := time.Since(debut); duree > 2*time.Second {
		t.Errorf("la sortie a attendu %v un parcours bloqué", duree)
	}
}

// TestAfficherPrefereLaReponseDeposee : quand la réponse de l'écran est déjà
// déposée et que l'hôte se ferme en même temps (Ctrl+C), afficher rend la
// réponse — le modèle final et son erreur — plutôt que nil au hasard du
// select.
func TestAfficherPrefereLaReponseDeposee(t *testing.T) {
	attendu := texteFixe{"modèle final"}
	for range 200 {
		var h *hote
		h = nouvelHote(func(msg tea.Msg) {
			d := msg.(demandeEcran)
			d.reponse <- resultatEcran{modele: attendu, err: huh.ErrUserAborted}
			h.fermer()
		})
		modele, err := h.afficher(&ecranDeTest{modele: texteFixe{"écran"}})
		if modele != attendu || !errors.Is(err, huh.ErrUserAborted) {
			t.Fatalf("afficher = (%v, %v), attendu (%v, ErrUserAborted)", modele, err, attendu)
		}
	}
}

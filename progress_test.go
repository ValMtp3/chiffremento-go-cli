package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func demoModel(ratio float64, largeur int) *progressModel {
	var done atomic.Int64
	total := int64(14_900_000)
	done.Store(int64(float64(total) * ratio))

	m := newProgressModel(jobInfo{
		Action: "chiffrement",
		In:     "rapport-annuel.pdf",
		Out:    "rapport-annuel.pdf.chto",
		Size:   total,
		AEAD:   "aes-256-gcm",
		KDF:    "argon2id  m=256MiB t=3 p=4",
		Salt:   "16 o aléatoires · en-tête authentifié",
	}, &done, largeur)
	return m
}

// hauteurProgression : le nombre de lignes de l'écran, cadre des détails
// compris (9 lignes de texte et 2 de bordure).
const hauteurProgression = 11

// largeursTestees : des largeurs que l'hôte peut donner à l'écran, de la plus
// étroite (48 : l'intérieur du cadre minimal de 52 colonnes) à la plus large.
var largeursTestees = []int{48, 52, 64, 80}

// TestRenduLargeurConstante garantit la promesse de la DA : la mise en page ne
// bouge pas pendant l'opération. Toutes les lignes ont exactement la largeur
// donnée par le cadre, quel que soit l'avancement, et rien n'est replié — un
// repli ajouterait des lignes et ferait sauter la barre.
func TestRenduLargeurConstante(t *testing.T) {
	for _, largeur := range largeursTestees {
		for _, ratio := range []float64{0, 0.01, 0.5, 0.74, 0.999, 1} {
			m := demoModel(ratio, largeur)
			m.info.In = strings.Repeat("nom-de-fichier-tres-long-", 6) + ".pdf"
			lines := strings.Split(m.View(), "\n")
			for i, line := range lines {
				if w := lipgloss.Width(line); w != largeur {
					t.Errorf("largeur %d, ratio %.2f : la ligne %d fait %d colonnes\n%q",
						largeur, ratio, i, w, line)
				}
			}
			if len(lines) != hauteurProgression {
				t.Errorf("largeur %d, ratio %.2f : %d lignes au lieu de %d (repli ?)",
					largeur, ratio, len(lines), hauteurProgression)
			}
		}
	}
}

// TestProgressionSuitLeCadre : l'écran prend la largeur que l'hôte lui donne
// au redimensionnement, sans attendre une autre image.
func TestProgressionSuitLeCadre(t *testing.T) {
	m := demoModel(0.5, 52)
	m.Update(tea.WindowSizeMsg{Width: 72, Height: 20})
	for i, line := range strings.Split(m.View(), "\n") {
		if w := lipgloss.Width(line); w != 72 {
			t.Errorf("après redimensionnement, la ligne %d fait %d colonnes au lieu de 72", i, w)
		}
	}
}

// TestRenduSansCouleur vérifie qu'aucun emoji ni glyphe exotique ne s'est
// glissé dans l'affichage : seuls le box-drawing simple ligne et les blocs
// pleins sont autorisés, ils existent dans toutes les polices mono.
func TestRenduSansCouleur(t *testing.T) {
	autorises := "─│┌┐└┘█░·…✓"
	view := demoModel(0.5, contentWidth).View()

	for _, r := range view {
		if r < 0x80 || strings.ContainsRune(autorises, r) {
			continue
		}
		// Les lettres accentuées restent évidemment acceptables.
		if r >= 0xC0 && r <= 0x17F {
			continue
		}
		t.Errorf("caractère non prévu par la DA dans l'affichage : %q (U+%04X)", r, r)
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		0:          "0 o",
		512:        "512 o",
		1024:       "1.0 ko",
		14_900_000: "14.2 Mo",
	}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, attendu %q", in, got, want)
		}
	}
}

// TestAnimationVisible : sur un petit fichier, l'opération est finie avant la
// première image. La barre doit malgré tout se dérouler sur minDuration, sans
// jamais dépasser la progression réelle.
func TestAnimationVisible(t *testing.T) {
	var done atomic.Int64
	total := int64(1000)
	m := newProgressModel(jobInfo{Action: "chiffrement", Size: total}, &done, contentWidth)

	// Opération instantanée : 100 % des octets traités dès le départ.
	done.Store(total)
	m.opDone = true

	if r := m.displayRatio(); r > 0.2 {
		t.Errorf("la barre est déjà à %.0f%% à t=0 : l'animation ne serait pas visible", r*100)
	}

	m.start = m.start.Add(-minDuration / 2)
	if r := m.displayRatio(); r < 0.4 || r > 0.6 {
		t.Errorf("à mi-durée la barre devrait être à ~50%%, elle est à %.0f%%", r*100)
	}

	m.start = m.start.Add(-minDuration)
	if r := m.displayRatio(); r != 1 {
		t.Errorf("après minDuration la barre devrait être pleine, elle est à %.0f%%", r*100)
	}
}

// TestAnimationNeDepassePasLeReel : sur un gros fichier lent, c'est la
// progression réelle qui pilote, jamais le minuteur.
func TestAnimationNeDepassePasLeReel(t *testing.T) {
	var done atomic.Int64
	total := int64(1000)
	m := newProgressModel(jobInfo{Size: total}, &done, contentWidth)

	done.Store(300) // 30 % réellement traités
	m.start = m.start.Add(-10 * minDuration)

	if r := m.displayRatio(); r != 0.3 {
		t.Errorf("la barre affiche %.0f%% alors que seuls 30%% sont traités", r*100)
	}
}

// TestDureeEcranReelle fait tourner le vrai runJob sans terminal et mesure sa
// durée. Ce test a attrapé un blocage : quand le compteur d'octets n'atteint
// pas exactement le total — au déchiffrement, l'en-tête est lu avant que le
// compteur soit branché — l'écran ne se fermait jamais.
func TestDureeEcranReelle(t *testing.T) {
	teaOptions = []tea.ProgramOption{tea.WithInput(nil), tea.WithOutput(io.Discard)}
	defer func() { teaOptions = nil }()

	cases := map[string]func(p func(int64, int64)) error{
		"compteur complet":   func(p func(int64, int64)) error { p(1000, 1000); return nil },
		"compteur incomplet": func(p func(int64, int64)) error { p(1, 1000000); return nil },
		"aucune progression": func(p func(int64, int64)) error { return nil },
	}

	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if err := runJob(jobInfo{Action: "test", In: "/etc/hosts", Success: "ok"}, op); err != nil {
				t.Fatal(err)
			}
			d := time.Since(start)
			switch {
			case d < minDuration:
				t.Errorf("écran fermé en %v : l'animation n'aurait pas été visible", d)
			case d > 3*minDuration:
				t.Errorf("écran resté ouvert %v : blocage", d)
			}
		})
	}
}

// TestCtrlCInterromptLaProgression : un chiffrement de 50 Go doit pouvoir être
// annulé. Ctrl+C arrivait en mode brut comme une simple touche, et Update
// l'ignorait : aucun retour visuel, aucune sortie possible. runJob sait déjà
// traiter tea.ErrInterrupted (temporaires nettoyés, code 130).
func TestCtrlCInterromptLaProgression(t *testing.T) {
	var done atomic.Int64
	m := newProgressModel(jobInfo{Action: "chiffrement", Size: 100}, &done, contentWidth)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("Ctrl+C ignoré : aucune commande renvoyée")
	}
	if _, ok := cmd().(tea.InterruptMsg); !ok {
		t.Errorf("Ctrl+C renvoie %T, attendu tea.InterruptMsg", cmd())
	}
}

// progressionDeTest construit un écran de progression branché sur fin, comme
// le fait runJob.
func progressionDeTest(fin chan error) *progressModel {
	var done atomic.Int64
	m := newProgressModel(jobInfo{Action: "chiffrement", In: "a.txt", Out: "a.txt.chto", Size: 100}, &done, contentWidth)
	m.fin = fin
	return m
}

// TestEchapPendantEcritureIgnore : pendant la progression, l'écriture est
// lancée ; Échap ne doit pas l'abandonner à moitié (Review Focus 3). L'écran
// reste affiché et le parcours n'obtient aucune réponse.
func TestEchapPendantEcritureIgnore(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	// Les commandes d'Init ne sont pas déroulées : elles attendraient la fin
	// d'une opération qui ne vient pas.
	demande := nouvelleDemande(progressionDeTest(make(chan error)))
	h.Update(demande)
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
	if r, recue := reponseRecue(t, demande); recue {
		t.Fatalf("Échap a terminé l'écran de progression : %+v", r)
	}
	if !strings.Contains(h.View(), "aead") {
		t.Errorf("l'écran de progression n'est plus affiché après Échap :\n%s", h.View())
	}
}

// TestAidePendantProgression : ? ouvre l'aide par-dessus la progression, mais
// l'opération continue : sa fin arrive à l'écran resté dessous, et la
// progression revient quand l'aide se referme.
func TestAidePendantProgression(t *testing.T) {
	h := hoteDeTest(t, 100, 30)
	fin := make(chan error, 1)
	m := progressionDeTest(fin)
	_, init := h.Update(nouvelleDemande(m))
	// Init attend la fin de l'opération : on ne déroule sa commande qu'après
	// l'avoir déposée, sinon le test attendrait pour toujours.
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if !strings.Contains(h.View(), "aide") || strings.Contains(h.View(), "aead") {
		t.Fatalf("? n'a pas ouvert l'aide par-dessus la progression :\n%s", h.View())
	}
	fin <- nil
	derouleSansTick(t, h, init)
	if !m.opDone {
		t.Error("la fin de l'opération n'a pas atteint l'écran de progression pendant l'aide")
	}
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if !strings.Contains(h.View(), "aead") {
		t.Errorf("la progression n'est pas revenue après l'aide :\n%s", h.View())
	}
}

// derouleSansTick déroule une commande de l'hôte en ignorant les ticks
// d'animation, qui se réarment sans fin.
func derouleSansTick(t *testing.T, h *hote, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	switch msg := cmd().(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			derouleSansTick(t, h, c)
		}
	case messageEcran:
		if _, tick := msg.msg.(tickMsg); tick {
			return
		}
		h.Update(msg)
	default:
		h.Update(msg)
	}
}

// lancerHoteDeTest fait tourner un vrai programme d'hôte, sans terminal, et le
// déclare comme hôte du plein écran le temps du test.
func lancerHoteDeTest(t *testing.T) (*hote, *tea.Program, chan bool) {
	t.Helper()
	h := nouvelHote(nil)
	p := programmeSansTerminal(t, h)
	fin := make(chan bool, 1)
	go func() {
		interrompu, _ := h.executer(p)
		fin <- interrompu
	}()
	p.Send(tea.WindowSizeMsg{Width: 100, Height: 30})
	hoteCourant, sessionCourante = h, &session{}
	t.Cleanup(func() {
		hoteCourant, sessionCourante = nil, nil
		p.Kill()
	})
	return h, p, fin
}

// TestRunJobDansLHote : en plein écran, runJob affiche la progression dans le
// cadre de l'hôte — pas de programme à lui, pas de terminal prêté — et rend
// l'erreur de l'opération. Le programme de l'hôte continue ensuite.
func TestRunJobDansLHote(t *testing.T) {
	h, _, fin := lancerHoteDeTest(t)

	attendue := errors.New("phrase refusée")
	err := runJob(jobInfo{Action: "test", In: "/etc/hosts"}, func(func(int64, int64)) error { return attendue })
	if !errors.Is(err, attendue) {
		t.Fatalf("runJob = %v, attendu %v", err, attendue)
	}

	debut := time.Now()
	if err := runJob(jobInfo{Action: "test", In: "/etc/hosts", Success: "ok"}, func(p func(int64, int64)) error {
		p(1, 2)
		return nil
	}); err != nil {
		t.Fatalf("runJob = %v, attendu nil", err)
	}
	if d := time.Since(debut); d < minDuration {
		t.Errorf("écran fermé en %v : l'animation n'aurait pas été visible", d)
	}
	select {
	case <-fin:
		t.Fatal("le programme de l'hôte s'est arrêté avec l'opération")
	case <-h.termine:
		t.Fatal("l'hôte a été fermé par l'opération")
	default:
	}
}

// TestRunJobCtrlCDansLHote : Ctrl+C pendant la progression termine le
// programme en interruption — runTUI nettoie alors les temporaires et sort en
// 130 ; aucun os.Exit dans runJob. runJob, lui, ne rend la main
// (huh.ErrUserAborted) qu'une fois l'opération finie : l'appelant efface le
// mot de passe juste après, et l'opération pourrait encore le lire.
func TestRunJobCtrlCDansLHote(t *testing.T) {
	_, p, fin := lancerHoteDeTest(t)
	bloque := make(chan struct{})

	issue := make(chan error, 1)
	go func() {
		issue <- runJob(jobInfo{Action: "test", In: "/etc/hosts"}, func(func(int64, int64)) error {
			<-bloque // une écriture qui n'en finit pas
			return nil
		})
	}()
	time.Sleep(100 * time.Millisecond) // le temps que l'écran s'ouvre
	p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})

	select {
	case interrompu := <-fin:
		if !interrompu {
			t.Error("Ctrl+C n'a pas été vu comme une interruption")
		}
	case <-time.After(delaiTest):
		t.Fatal("Ctrl+C n'a pas terminé le programme")
	}
	select {
	case err := <-issue:
		t.Fatalf("runJob a rendu la main (%v) avant la fin de l'opération", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(bloque)
	if err := issueRecue(t, issue); !errors.Is(err, huh.ErrUserAborted) {
		t.Fatalf("runJob = %v, attendu huh.ErrUserAborted", err)
	}
}

// TestProgressionDansLeCadreDeLHote : composée par l'hôte, la progression
// tient dans des cadres de 52, 64 et 80 colonnes sans qu'aucune ligne soit
// coupée (« … ») ni ne déborde du terminal.
func TestProgressionDansLeCadreDeLHote(t *testing.T) {
	for _, terminal := range []int{56, 68, 84} {
		h := hoteDeTest(t, terminal, 30)
		h.Update(nouvelleDemande(progressionDeTest(nil)))
		vue := h.View()
		if strings.Contains(vue, "…") || !strings.Contains(vue, "aead") {
			t.Errorf("cadre de %d colonnes : progression coupée ou absente\n%s", largeurCadre(terminal), vue)
		}
		for i, ligne := range strings.Split(vue, "\n") {
			if w := lipgloss.Width(ligne); w > terminal {
				t.Errorf("terminal de %d colonnes : la ligne %d en fait %d", terminal, i, w)
			}
		}
	}
}

// TestProgressionAutonomeLargeurFixe : hors de l'hôte (TERM=dumb), l'écran
// garde sa largeur historique. Bubble Tea envoie la taille du terminal au
// démarrage : elle ne doit pas étirer le cadre à 200 colonnes.
func TestProgressionAutonomeLargeurFixe(t *testing.T) {
	m := demoModel(0.5, contentWidth+2)
	m.autonome = true
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	for i, ligne := range strings.Split(strings.Trim(m.View(), "\n"), "\n") {
		if i == 0 {
			continue // la ligne de titre est hors cadre
		}
		if w := lipgloss.Width(ligne); w != contentWidth+2 {
			t.Errorf("ligne %d : %d colonnes au lieu de %d", i, w, contentWidth+2)
		}
	}
}

// TestProgressionAutonomeVersionAvecV : l'écran de progression autonome
// préfixe la version de « v », comme la barre du haut de l'hôte.
func TestProgressionAutonomeVersionAvecV(t *testing.T) {
	avant := version
	t.Cleanup(func() { version = avant })
	version = "2.4.0"
	m := demoModel(0.5, contentWidth+2)
	m.autonome = true
	m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	titre := ansi.Strip(strings.Split(strings.Trim(m.View(), "\n"), "\n")[0])
	if !strings.Contains(titre, " v2.4.0") {
		t.Errorf("titre sans « v2.4.0 » : %q", titre)
	}
}

// TestRunJobApresFermetureNeLancePasLOperation : si Ctrl+C a déjà fermé
// l'hôte, runJob ne lance pas l'opération — elle écrirait un temporaire
// pendant que le processus sort.
func TestRunJobApresFermetureNeLancePasLOperation(t *testing.T) {
	h := nouvelHote(func(tea.Msg) {})
	h.fermer()
	hoteCourant = h
	t.Cleanup(func() { hoteCourant = nil })

	lancee := false
	err := runJob(jobInfo{Action: "test", In: "/etc/hosts"}, func(func(int64, int64)) error {
		lancee = true
		return nil
	})
	if !errors.Is(err, huh.ErrUserAborted) {
		t.Errorf("runJob = %v, attendu huh.ErrUserAborted", err)
	}
	if lancee {
		t.Error("l'opération a été lancée alors que l'hôte est fermé")
	}
}

// TestPaniqueDeLOperationDevientErreur : une panique dans la goroutine de
// l'opération ne tue plus le processus terminal cassé : elle est rattrapée,
// les temporaires sont fermés, et elle remonte comme une erreur qui porte
// la valeur et la pile d'origine.
func TestPaniqueDeLOperationDevientErreur(t *testing.T) {
	appels := remplacerFermerTemporaires(t)
	modele, finie := lancerOperation(jobInfo{Action: "test", In: "/etc/hosts"},
		func(func(int64, int64)) error { panic("boum dans l'opération") }, 80)
	select {
	case <-finie:
	case <-time.After(delaiTest):
		t.Fatal("l'opération n'a pas rendu la main")
	}
	err := <-modele.fin
	var p *paniqueOperation
	if !errors.As(err, &p) || p.valeur != "boum dans l'opération" {
		t.Fatalf("erreur = %v, attendu une paniqueOperation « boum dans l'opération »", err)
	}
	if !strings.Contains(string(p.pile), "TestPaniqueDeLOperationDevientErreur") {
		t.Errorf("la pile ne montre pas l'origine :\n%s", p.pile)
	}
	if appels.Load() != 1 {
		t.Errorf("FermerTemporaires appelée %d fois, attendu 1", appels.Load())
	}
}

// TestPaniqueDeLOperationSuitLeCheminDeF5 : le parcours qui reçoit cette
// erreur relance la panique ; gardeParcours la note avec la valeur et la
// pile de l'opération, pas celles du parcours, et rend le terminal.
func TestPaniqueDeLOperationSuitLeCheminDeF5(t *testing.T) {
	origine := &paniqueOperation{valeur: "boum", pile: []byte("pile de l'opération")}
	var garde gardeParcours
	rendu := false
	garde.mener(func() { relancerPanique(fmt.Errorf("chiffrement : %w", origine)) }, func() { rendu = true })
	note := garde.panique.Load()
	if note == nil || note.valeur != "boum" || string(note.pile) != "pile de l'opération" {
		t.Fatalf("panique notée = %+v", note)
	}
	if !rendu {
		t.Error("rendre n'a pas été appelé")
	}
	relancerPanique(errors.New("erreur ordinaire")) // ne panique pas
	relancerPanique(nil)
}

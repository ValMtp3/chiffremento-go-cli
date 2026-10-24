package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"chiffremento-cli/pkg"
)

// Phrase gardée pour la session (R-TUI-12) : copie à la garde et à la prise,
// oubli au délai, par o et à la sortie, un seul minuteur à la fois.

// horlogeDeTest avance à la main : aucun test n'attend cinq vraies minutes.
// Elle tient séparément l'heure murale et l'horloge monotone, pour simuler ce
// qui les fait diverger : une mise en veille (la monotone s'arrête) ou un
// réglage de l'heure (la murale saute).
type horlogeDeTest struct {
	mur  time.Time
	mono time.Duration
}

func (h *horlogeDeTest) maintenant() instant { return instant{mur: h.mur, mono: h.mono} }

// avancer : le temps passe pour les deux horloges.
func (h *horlogeDeTest) avancer(d time.Duration) { h.mur, h.mono = h.mur.Add(d), h.mono+d }

// deplacerMur : seule l'heure murale bouge (réglage, NTP, veille).
func (h *horlogeDeTest) deplacerMur(d time.Duration) { h.mur = h.mur.Add(d) }

// minuterieDeTest remplace tea.Tick : elle note chaque minuteur programmé et
// ne rend aucune commande. Le test déclenche lui-même l'échéance, en
// envoyant echeancePhraseMsg.
type minuterieDeTest struct{ delais []time.Duration }

func (m *minuterieDeTest) programmer(d time.Duration) tea.Cmd {
	m.delais = append(m.delais, d)
	return nil
}

// hoteAvecPhrase : un hôte de test qui connaît la phrase de session, avec une
// horloge et une minuterie de test.
func hoteAvecPhrase(t *testing.T) (*hote, *phraseSession, *horlogeDeTest, *minuterieDeTest) {
	t.Helper()
	h := hoteDeTest(t, 100, 30)
	horloge := &horlogeDeTest{mur: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	minuterie := &minuterieDeTest{}
	p := &phraseSession{horloge: horloge.maintenant}
	h.phrase, h.minuterie = p, minuterie.programmer
	return h, p, horloge, minuterie
}

// garderSurLHote garde une phrase comme le parcours, puis prévient l'hôte. Rend
// le tableau gardé, pour vérifier ensuite qu'il a bien été mis à zéro.
func garderSurLHote(t *testing.T, h *hote, p *phraseSession, phrase string) []byte {
	t.Helper()
	p.garder([]byte(phrase))
	garde := p.octets
	envoyerHote(t, h, phraseGardeeMsg{})
	return garde
}

func toutAZero(b []byte) bool {
	for _, o := range b {
		if o != 0 {
			return false
		}
	}
	return true
}

func indicateurAffiche(h *hote) bool {
	return strings.Contains(strings.Split(h.View(), "\n")[0], "● phrase en mémoire")
}

// TestPrendreRendUneCopie : la session garde sa propre copie, et chaque prise
// en rend une neuve. L'appelant peut effacer la sienne sans rien abîmer.
func TestPrendreRendUneCopie(t *testing.T) {
	var p phraseSession
	secret := []byte("correct horse battery staple")
	p.garder(secret)
	zero(secret) // l'appelant efface la sienne aussitôt

	prise, ok := p.prendre()
	if !ok || string(prise) != "correct horse battery staple" {
		t.Fatalf("prendre = (%q, %v)", prise, ok)
	}
	if &prise[0] == &p.octets[0] {
		t.Fatal("prendre rend le tableau de la session, pas une copie")
	}
	zero(prise)
	encore, ok := p.prendre()
	if !ok || string(encore) != "correct horse battery staple" {
		t.Fatalf("effacer la copie prise a abîmé la phrase gardée : %q", encore)
	}

	// Garder une autre phrase efface la précédente.
	ancienne := p.octets
	p.garder([]byte("autre phrase"))
	if !toutAZero(ancienne) {
		t.Errorf("l'ancienne phrase n'a pas été mise à zéro : %q", ancienne)
	}

	var vide phraseSession
	if _, ok := vide.prendre(); ok {
		t.Error("prendre sans phrase gardée rend ok")
	}
	var absente *phraseSession
	if absente.active() {
		t.Error("une session absente a une phrase active")
	}
}

// TestPhraseOublieeApresDelai (Review Focus 4) : cinq minutes sans touche, et
// les octets sont à zéro, l'indicateur éteint — même pendant l'écran de
// progression, qui ne reçoit aucune touche. Une touche repousse l'échéance.
func TestPhraseOublieeApresDelai(t *testing.T) {
	h, p, horloge, minuterie := hoteAvecPhrase(t)
	montrer(t, h, &ecranDeTest{modele: texteFixe{"chiffrement en cours"}, titre: "progression", echap: true})

	garde := garderSurLHote(t, h, p, "correct horse battery staple")
	if !indicateurAffiche(h) {
		t.Fatalf("indicateur absent après la garde :\n%s", h.View())
	}
	if len(minuterie.delais) != 1 || minuterie.delais[0] != delaiOubli {
		t.Fatalf("minuteurs programmés = %v, attendu un seul de %v", minuterie.delais, delaiOubli)
	}

	// Une touche à 2 min repousse l'échéance à 7 min.
	horloge.avancer(2 * time.Minute)
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})

	// À 5 min, le minuteur arrive : la phrase vit encore, un seul minuteur est
	// reprogrammé pour le reste.
	horloge.avancer(3 * time.Minute)
	envoyerHote(t, h, echeancePhraseMsg{})
	if !p.active() || toutAZero(garde) {
		t.Fatal("phrase oubliée alors qu'une touche avait repoussé l'échéance")
	}
	if len(minuterie.delais) != 2 || minuterie.delais[1] != 2*time.Minute {
		t.Fatalf("minuteurs programmés = %v, attendu un second de 2m0s", minuterie.delais)
	}

	// À 7 min, sans touche depuis 5 min : oubliée.
	horloge.avancer(2 * time.Minute)
	envoyerHote(t, h, echeancePhraseMsg{})
	if p.active() {
		t.Error("phrase encore active après le délai")
	}
	if !toutAZero(garde) {
		t.Errorf("octets non mis à zéro après le délai : %q", garde)
	}
	if indicateurAffiche(h) {
		t.Errorf("indicateur encore affiché après l'oubli :\n%s", h.View())
	}
	if len(minuterie.delais) != 2 {
		t.Errorf("un minuteur programmé sans phrase gardée : %v", minuterie.delais)
	}

	// Échéance passée mais minuteur pas encore arrivé : la phrase ne sert
	// déjà plus, et une touche ne la ranime pas.
	garde = garderSurLHote(t, h, p, "seconde phrase")
	horloge.avancer(delaiOubli)
	if _, ok := p.prendre(); ok {
		t.Error("une phrase échue a encore été rendue")
	}
	// Au réveil d'une mise en veille, le minuteur arrive en retard : la
	// première touche efface déjà la phrase, sans la ranimer.
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if p.active() || !toutAZero(garde) {
		t.Errorf("une touche après l'échéance n'a pas effacé la phrase : %q", garde)
	}
}

// enregistreur est un modèle qui note les touches reçues.
type enregistreur struct{ recu *[]string }

func (m enregistreur) Init() tea.Cmd { return nil }
func (m enregistreur) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		*m.recu = append(*m.recu, k.String())
	}
	return m, nil
}
func (m enregistreur) View() string { return "écran" }

// TestToucheOOublie : o oublie la phrase sur un écran sans champ texte, menu
// compris ; dans un champ texte, o est une lettre de la phrase tapée.
func TestToucheOOublie(t *testing.T) {
	t.Run("écran sans saisie", func(t *testing.T) {
		h, p, _, _ := hoteAvecPhrase(t)
		var recu []string
		montrer(t, h, &ecranDeTest{modele: enregistreur{&recu}, titre: "menu"})
		garde := garderSurLHote(t, h, p, "correct horse battery staple")

		taper(t, h, "o")
		if p.active() || !toutAZero(garde) {
			t.Errorf("o n'a pas oublié la phrase : active=%v, octets %q", p.active(), garde)
		}
		if indicateurAffiche(h) {
			t.Error("indicateur encore affiché après o")
		}
		if len(recu) != 0 {
			t.Errorf("o a aussi atteint l'écran : %v", recu)
		}
		// Sans phrase gardée, o redevient une touche ordinaire de l'écran.
		taper(t, h, "o")
		if len(recu) != 1 || recu[0] != "o" {
			t.Errorf("o sans phrase gardée n'est pas transmis à l'écran : %v", recu)
		}
	})
	t.Run("pendant une saisie", func(t *testing.T) {
		h, p, _, _ := hoteAvecPhrase(t)
		var recu []string
		montrer(t, h, &ecranDeTest{modele: enregistreur{&recu}, titre: "mot de passe", saisie: true})
		garderSurLHote(t, h, p, "correct horse battery staple")

		taper(t, h, "o")
		if !p.active() {
			t.Error("o a oublié la phrase pendant une saisie")
		}
		if len(recu) != 1 || recu[0] != "o" {
			t.Errorf("o tapé dans un champ texte n'a pas atteint le champ : %v", recu)
		}
	})
}

// TestPhraseOublieeALaSortie : la phrase est mise à zéro à la sortie, normale
// ou par Ctrl+C, avant que main n'appelle os.Exit — et rien ne peut plus être
// gardé ensuite, même par un parcours encore en vie.
func TestPhraseOublieeALaSortie(t *testing.T) {
	t.Run("ctrl+c", func(t *testing.T) {
		h, p, _, _ := hoteAvecPhrase(t)
		montrer(t, h, &ecranDeTest{modele: texteFixe{"x"}, titre: "progression", echap: true})
		garde := garderSurLHote(t, h, p, "correct horse battery staple")

		h.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		if p.active() || !toutAZero(garde) {
			t.Errorf("Ctrl+C n'a pas effacé la phrase : %q", garde)
		}
		p.garder([]byte("trop tard"))
		if p.active() {
			t.Error("une phrase a été gardée après la sortie")
		}
	})
	t.Run("quitter", func(t *testing.T) {
		horloge := &horlogeDeTest{mur: time.Now()}
		p := &phraseSession{horloge: horloge.maintenant}
		minuterie := &minuterieDeTest{}
		var programme *tea.Program
		h := nouvelHote(func(msg tea.Msg) { programme.Send(msg) })
		h.phrase, h.minuterie = p, minuterie.programmer
		programme = tea.NewProgram(h, tea.WithInput(nil), tea.WithOutput(io.Discard))
		p.garder([]byte("correct horse battery staple"))
		garde := p.octets

		fini := make(chan bool, 1)
		go func() {
			interrompu, _ := h.executer(programme)
			fini <- interrompu
		}()
		h.signalerPhraseGardee()
		h.quitter()
		select {
		case interrompu := <-fini:
			if interrompu {
				t.Error("quitter compté comme une interruption")
			}
		case <-time.After(delaiTest):
			t.Fatal("le programme n'est pas sorti")
		}
		if p.active() || !toutAZero(garde) {
			t.Errorf("la sortie normale n'a pas effacé la phrase : %q", garde)
		}
	})
}

// TestUnSeulMinuteur : aucun minuteur sans phrase gardée ; un seul en attente
// quand une phrase l'est, quel que soit le nombre de touches.
func TestUnSeulMinuteur(t *testing.T) {
	h, p, horloge, minuterie := hoteAvecPhrase(t)
	montrer(t, h, &ecranDeTest{modele: texteFixe{"menu"}, titre: "menu"})

	taper(t, h, "abc")
	envoyerHote(t, h, phraseGardeeMsg{})
	envoyerHote(t, h, echeancePhraseMsg{})
	if len(minuterie.delais) != 0 {
		t.Fatalf("minuteurs programmés sans phrase gardée : %v", minuterie.delais)
	}

	garderSurLHote(t, h, p, "correct horse battery staple")
	garderSurLHote(t, h, p, "une autre phrase")
	for range 20 {
		horloge.avancer(time.Second)
		taper(t, h, "x")
	}
	if len(minuterie.delais) != 1 {
		t.Fatalf("%d minuteurs programmés, attendu un seul : %v", len(minuterie.delais), minuterie.delais)
	}
	// À son arrivée, l'échéance a reculé de 20 s : un seul autre, pour ces 20 s.
	horloge.avancer(delaiOubli - 20*time.Second)
	envoyerHote(t, h, echeancePhraseMsg{})
	if len(minuterie.delais) != 2 || minuterie.delais[1] != 20*time.Second {
		t.Fatalf("minuteurs programmés = %v, attendu un second de 20s", minuterie.delais)
	}
}

// TestGarderDemandeAccord : après une opération réussie, la question « garder
// cette phrase pour la session ? » part sur non ; rien n'est gardé sans oui,
// ni sur Échap.
func TestGarderDemandeAccord(t *testing.T) {
	cas := []struct {
		nom     string
		touches []tea.KeyMsg
		garde   bool
	}{
		{"défaut", []tea.KeyMsg{touche("enter")}, false},
		{"échap", []tea.KeyMsg{{Type: tea.KeyEsc}}, false},
		{"oui", []tea.KeyMsg{touche("up"), touche("enter")}, true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			h, boite := hoteSynchrone(t, 100, 30)
			minuterie := &minuterieDeTest{}
			s := &session{}
			sessionCourante = s
			t.Cleanup(func() { sessionCourante = nil })
			h.phrase, h.minuterie = &s.phrase, minuterie.programmer

			secret := []byte("correct horse battery staple")
			issue := make(chan error, 1)
			go func() { issue <- proposerDeGarder(secret) }()
			demandeRecue(t, h, boite)
			if !strings.Contains(h.View(), "garder cette phrase pour la session ?") {
				t.Fatalf("question absente :\n%s", h.View())
			}
			if !strings.Contains(h.View(), curseurHuh+"ne pas la garder") {
				t.Errorf("le curseur ne part pas sur « ne pas la garder » :\n%s", h.View())
			}
			for _, k := range c.touches {
				envoyerHote(t, h, k)
			}
			if err := issueRecue(t, issue); err != nil {
				t.Fatalf("proposerDeGarder = %v", err)
			}
			if s.phrase.active() != c.garde {
				t.Fatalf("phrase gardée = %v, attendu %v", s.phrase.active(), c.garde)
			}
			if !c.garde {
				return
			}
			prise, _ := s.phrase.prendre()
			if !bytes.Equal(prise, secret) {
				t.Errorf("phrase gardée %q, attendu %q", prise, secret)
			}
			// L'hôte est prévenu : il arme le minuteur d'oubli.
			select {
			case msg := <-boite:
				envoyerHote(t, h, msg)
			case <-time.After(delaiTest):
				t.Fatal("l'hôte n'a pas été prévenu de la garde")
			}
			if len(minuterie.delais) != 1 {
				t.Errorf("minuteurs après la garde = %v, attendu un seul", minuterie.delais)
			}
		})
	}
}

// curseurHuh précède l'option sous le curseur dans une liste huh.
const curseurHuh = "> "

// TestPhraseProposeeALaSaisie : avec une phrase gardée, l'écran du mot de
// passe demande d'abord s'il faut l'utiliser (oui par défaut) ; « la saisir »
// montre le champ habituel.
func TestPhraseProposeeALaSaisie(t *testing.T) {
	t.Run("utiliser", func(t *testing.T) {
		password, saisir := "", false
		form, ancre := passwordFormMemoire("détails", &password, &saisir)
		m := ouvrirEtape(t, form, ancre)
		if !strings.Contains(m.View(), curseurHuh+"utiliser la phrase en mémoire") {
			t.Fatalf("« utiliser » n'est pas proposé par défaut :\n%s", m.View())
		}
		envoyerEtape(t, m, touche("enter"))
		if form.State != huh.StateCompleted || saisir {
			t.Errorf("entrée n'a pas retenu la phrase en mémoire : état %v, saisir %v", form.State, saisir)
		}
	})
	t.Run("la saisir", func(t *testing.T) {
		password, saisir := "", false
		form, ancre := passwordFormMemoire("détails", &password, &saisir)
		m := ouvrirEtape(t, form, ancre)
		envoyerEtape(t, m, touche("down"))
		envoyerEtape(t, m, touche("enter"))
		if _, ok := form.GetFocusedField().(*huh.Input); !ok || !saisir {
			t.Fatalf("« la saisir » ne montre pas le champ : %T, saisir %v", form.GetFocusedField(), saisir)
		}
	})
	t.Run("chiffrement", func(t *testing.T) {
		o := optionsChiffrement{}
		appliquerDefauts(&o, false)
		o.memoire = true
		form, ancre := encryptForm(&o, false, -1)
		m := ouvrirEtape(t, form, ancre)
		// algorithme, coût, compression, masquage, nom d'origine, puis la
		// question de la phrase en mémoire : ni génération, ni saisie, ni
		// confirmation ensuite — la phrase a déjà été validée.
		for range 5 {
			envoyerEtape(t, m, touche("enter"))
		}
		if !strings.Contains(m.View(), "utiliser la phrase en mémoire ?") {
			t.Fatalf("question de la phrase en mémoire absente :\n%s", m.View())
		}
		envoyerEtape(t, m, touche("enter"))
		if form.State != huh.StateCompleted {
			t.Fatalf("le formulaire demande encore quelque chose après la phrase en mémoire :\n%s", m.View())
		}
		if !depuisLaSession(&o) {
			t.Error("la phrase en mémoire n'est pas retenue pour chiffrer")
		}
	})
}

// TestPasswdNeProposePasLaPhrase : changer de mot de passe demande toujours
// une saisie, même avec une phrase gardée pour la session.
func TestPasswdNeProposePasLaPhrase(t *testing.T) {
	dossier := t.TempDir()
	clair, chiffre := filepath.Join(dossier, "coffre.txt"), filepath.Join(dossier, "coffre.txt.chto")
	poserFichier(t, clair, []byte("contenu"))
	if err := pkg.Encrypt(clair, chiffre, []byte("ancienne phrase"), pkg.Options{Algo: pkg.AlgoAES, KDF: pkg.KDFStandard}); err != nil {
		t.Fatal(err)
	}

	h, boite := hoteSynchrone(t, 100, 30)
	s := &session{}
	sessionCourante = s
	t.Cleanup(func() { sessionCourante = nil })
	h.phrase = &s.phrase
	s.phrase.garder([]byte("ancienne phrase"))

	issue := make(chan error, 1)
	go func() { issue <- tuiPasswd(chiffre) }()
	demandeRecue(t, h, boite) // lecture de l'en-tête, qui se ferme d'elle-même
	demandeRecue(t, h, boite)
	vue := h.View()
	if strings.Contains(vue, titreUtiliser) {
		t.Errorf("la phrase en mémoire est proposée pour changer de mot de passe :\n%s", vue)
	}
	if !strings.Contains(vue, "mot de passe actuel") {
		t.Errorf("le champ du mot de passe actuel n'est pas affiché :\n%s", vue)
	}
	envoyerHote(t, h, tea.KeyMsg{Type: tea.KeyEsc})
	if err := issueRecue(t, issue); !errors.Is(err, errMenu) {
		t.Errorf("tuiPasswd après Échap = %v, attendu errMenu", err)
	}
}

// TestPhraseOublieeMemeSiLHorlogeBouge : le délai vaut sur l'heure murale ET
// sur l'horloge monotone. Une heure murale qui recule (NTP, réglage) ne
// prolonge pas la phrase ; une veille (la monotone s'arrête, la murale
// avance) ne la prolonge pas non plus, et le premier message reçu après
// l'échéance efface les octets, sans attendre le minuteur en retard.
func TestPhraseOublieeMemeSiLHorlogeBouge(t *testing.T) {
	t.Run("heure murale qui recule", func(t *testing.T) {
		h, p, horloge, minuterie := hoteAvecPhrase(t)
		montrer(t, h, &ecranDeTest{modele: texteFixe{"menu"}, titre: "menu"})
		garde := garderSurLHote(t, h, p, "correct horse battery staple")

		horloge.deplacerMur(-365 * 24 * time.Hour)
		horloge.avancer(delaiOubli)
		envoyerHote(t, h, echeancePhraseMsg{})
		if p.active() || !toutAZero(garde) {
			t.Errorf("phrase prolongée par une heure murale qui recule : %q", garde)
		}
		if len(minuterie.delais) != 1 {
			t.Errorf("minuteur reprogrammé après le délai : %v", minuterie.delais)
		}
	})
	t.Run("veille", func(t *testing.T) {
		h, p, horloge, _ := hoteAvecPhrase(t)
		montrer(t, h, &ecranDeTest{modele: texteFixe{"progression"}, titre: "progression", echap: true})
		garde := garderSurLHote(t, h, p, "correct horse battery staple")

		// Une heure de capot fermé : la monotone n'a avancé que d'une minute.
		horloge.avancer(time.Minute)
		horloge.deplacerMur(time.Hour)
		// N'importe quel message, ici une image de l'animation, suffit.
		envoyerHote(t, h, messageEcran{id: h.idCourant, msg: tickMsg(horloge.mur)})
		if p.active() || !toutAZero(garde) {
			t.Errorf("phrase encore en mémoire après la veille : %q", garde)
		}
		if indicateurAffiche(h) {
			t.Error("indicateur encore affiché après la veille")
		}
	})
	t.Run("minuteur sur le plus court des deux restes", func(t *testing.T) {
		h, p, horloge, minuterie := hoteAvecPhrase(t)
		montrer(t, h, &ecranDeTest{modele: texteFixe{"menu"}, titre: "menu"})
		garderSurLHote(t, h, p, "correct horse battery staple")

		// Monotone +5 min (le minuteur arrive), murale +4 min seulement
		// (recul d'1 min entre-temps) : la monotone est échue, la phrase aussi.
		horloge.avancer(4 * time.Minute)
		horloge.mono += time.Minute
		envoyerHote(t, h, echeancePhraseMsg{})
		if p.active() {
			t.Fatal("phrase gardée alors que l'horloge monotone est échue")
		}

		// Murale +3 min, monotone +1 min : reste 2 min, pas 4.
		garderSurLHote(t, h, p, "seconde phrase")
		n := len(minuterie.delais)
		horloge.avancer(time.Minute)
		horloge.deplacerMur(2 * time.Minute)
		envoyerHote(t, h, echeancePhraseMsg{})
		if len(minuterie.delais) != n+1 || minuterie.delais[n] != 2*time.Minute {
			t.Errorf("minuteurs = %v, attendu un dernier de 2m0s", minuterie.delais)
		}
	})
}

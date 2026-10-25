package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// remplacerVerrouillage remplace le verrouillage de la plateforme le temps
// d'un test, et remet à zéro la raison notée.
func remplacerVerrouillage(t *testing.T, verrouiller, deverrouiller func([]byte) error) {
	t.Helper()
	anciens := [2]func([]byte) error{verrouillerMemoire, deverrouillerMemoire}
	verrouillerMemoire, deverrouillerMemoire = verrouiller, deverrouiller
	raisonNonVerrouille.Store(nil)
	t.Cleanup(func() {
		verrouillerMemoire, deverrouillerMemoire = anciens[0], anciens[1]
		raisonNonVerrouille.Store(nil)
	})
}

// TestPhraseGardeeVerrouillee : la phrase gardée vit dans une page à elle,
// alignée et verrouillée en mémoire vive ; l'oubli la met à zéro puis la
// déverrouille.
func TestPhraseGardeeVerrouillee(t *testing.T) {
	var verrouillees, deverrouillees [][]byte
	remplacerVerrouillage(t,
		func(b []byte) error { verrouillees = append(verrouillees, b); return nil },
		func(b []byte) error {
			if !toutAZero(b) {
				t.Error("page déverrouillée avant d'être mise à zéro")
			}
			deverrouillees = append(deverrouillees, b)
			return nil
		})

	var p phraseSession
	p.garder([]byte("correct horse battery staple"), "")
	if len(verrouillees) != 1 {
		t.Fatalf("%d pages verrouillées, attendu 1", len(verrouillees))
	}
	page := os.Getpagesize()
	if b := verrouillees[0]; len(b) != page || uintptr(unsafe.Pointer(&b[0]))%uintptr(page) != 0 {
		t.Errorf("la zone verrouillée n'est pas une page alignée : %d octets", len(b))
	}
	if &p.octets[0] != &verrouillees[0][0] {
		t.Error("la phrase n'est pas dans la page verrouillée")
	}
	if prise, ok := p.prendre(); !ok || string(prise) != "correct horse battery staple" {
		t.Errorf("prendre = (%q, %v)", prise, ok)
	}

	p.oublier()
	if len(deverrouillees) != 1 || &deverrouillees[0][0] != &verrouillees[0][0] {
		t.Fatalf("la page n'a pas été déverrouillée à l'oubli")
	}
	if !toutAZero(verrouillees[0]) {
		t.Error("la page n'est pas à zéro après l'oubli")
	}
	if raisonNonVerrouille.Load() != nil || noteVerrouillage() != "" {
		t.Errorf("une raison est notée alors que tout a réussi : %q", noteVerrouillage())
	}
}

// TestPhraseNonVerrouilleeContinue : si le verrouillage échoue (limite
// RLIMIT_MEMLOCK, plateforme), la phrase est gardée quand même, sans erreur ;
// la raison est notée une seule fois, et rien n'est déverrouillé.
func TestPhraseNonVerrouilleeContinue(t *testing.T) {
	refus := errors.New("limite atteinte")
	appels := 0
	remplacerVerrouillage(t,
		func([]byte) error { appels++; return refus },
		func([]byte) error { t.Error("déverrouillage d'une page jamais verrouillée"); return nil })

	var p phraseSession
	p.garder([]byte("première phrase"), "")
	p.garder([]byte("seconde phrase"), "")
	if prise, ok := p.prendre(); !ok || string(prise) != "seconde phrase" {
		t.Fatalf("prendre = (%q, %v)", prise, ok)
	}
	garde := p.octets
	p.oublier()
	if !toutAZero(garde) {
		t.Error("la phrase non verrouillée n'est pas à zéro après l'oubli")
	}
	raison := raisonNonVerrouille.Load()
	if raison == nil || !errors.Is(*raison, refus) {
		t.Fatalf("raison notée = %v, attendu %v", raison, refus)
	}
	if note := noteVerrouillage(); !strings.Contains(note, "limite atteinte") || !strings.Contains(note, "fichier d'échange") {
		t.Errorf("note de sortie = %q", note)
	}
	if appels != 2 {
		t.Errorf("%d essais de verrouillage, attendu un par garde", appels)
	}
}

// TestPhraseTropLonguePourUnePage : une phrase plus longue qu'une page est
// gardée sans verrouillage, et la raison le dit.
func TestPhraseTropLonguePourUnePage(t *testing.T) {
	remplacerVerrouillage(t,
		func([]byte) error { t.Error("verrouillage tenté pour une phrase trop longue"); return nil },
		func([]byte) error { return nil })
	var p phraseSession
	longue := strings.Repeat("a", os.Getpagesize()+1)
	p.garder([]byte(longue), "")
	if prise, ok := p.prendre(); !ok || string(prise) != longue {
		t.Fatal("la phrase trop longue n'est pas gardée")
	}
	if raisonNonVerrouille.Load() == nil {
		t.Error("aucune raison notée pour une phrase non verrouillée")
	}
}

// TestVerrouillageDeLaPlateforme : sur macOS et Linux, la vraie fonction
// verrouille et déverrouille une page sans erreur (une page tient dans la
// limite RLIMIT_MEMLOCK par défaut).
func TestVerrouillageDeLaPlateforme(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("vérifié sur macOS et Linux")
	}
	var p phraseSession
	raisonNonVerrouille.Store(nil)
	t.Cleanup(func() { raisonNonVerrouille.Store(nil) })
	p.garder([]byte("phrase verrouillée pour de vrai"), "")
	if p.tampon == nil || !p.tampon.verrouille {
		t.Fatalf("la page n'a pas été verrouillée : %v", raisonNonVerrouille.Load())
	}
	p.fermer()
	if p.tampon != nil {
		t.Error("le tampon survit à la fermeture")
	}
}

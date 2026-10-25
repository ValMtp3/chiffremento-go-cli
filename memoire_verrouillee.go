package main

import (
	"errors"
	"os"
	"sync/atomic"
	"unsafe"
)

// Mémoire verrouillée pour la phrase de session (R-TUI-12), au mieux.
//
// Une page verrouillée (mlock, VirtualLock) n'est jamais écrite dans le
// fichier d'échange du système : la phrase gardée pendant la session n'y
// laisse pas de trace. La page est prise dans le tas de Go, alignée dans une
// allocation de deux pages : le ramasse-miettes de Go ne déplace rien, et la
// page entière n'appartient qu'à la phrase — la verrouiller ne verrouille
// rien d'autre.
//
// Coût : deux pages (8 Kio sous Linux amd64, 32 Kio sous macOS arm64) tant
// qu'une phrase est gardée, un appel système à la garde et un à l'oubli, rien
// au repos.

// verrouillerMemoire et deverrouillerMemoire sont ceux de la plateforme
// (memoire_verrouillee_*.go) ; les tests les remplacent.
var (
	verrouillerMemoire   = verrouillerPlateforme
	deverrouillerMemoire = deverrouillerPlateforme
)

// errPhraseTropLongue : la phrase dépasse une page, elle est gardée sans
// verrouillage.
var errPhraseTropLongue = errors.New("phrase plus longue qu'une page mémoire")

// raisonNonVerrouille garde la première raison pour laquelle une phrase a
// été gardée sans verrouillage. La session la signale une fois, à la sortie.
var raisonNonVerrouille atomic.Pointer[error]

func noterNonVerrouille(err error) {
	raisonNonVerrouille.CompareAndSwap(nil, &err)
}

// noteVerrouillage rend la ligne imprimée à la sortie quand une phrase a été
// gardée sans verrouillage, "" sinon.
func noteVerrouillage() string {
	raison := raisonNonVerrouille.Load()
	if raison == nil {
		return ""
	}
	return "note : la phrase gardée n'a pas pu être verrouillée en mémoire vive (" + (*raison).Error() +
		") ; elle a pu passer dans le fichier d'échange du système\n"
}

// tamponSecret porte un secret, dans une page verrouillée si possible.
type tamponSecret struct {
	// support est l'allocation entière : elle reste référencée tant que la
	// page est verrouillée.
	support []byte
	// octets : la page verrouillée, ou une allocation ordinaire en repli.
	octets     []byte
	verrouille bool
}

// nouveauTamponSecret rend un tampon d'au moins n octets. Un verrouillage
// refusé n'est pas une erreur : le tampon est alors ordinaire, et la raison
// notée.
func nouveauTamponSecret(n int) *tamponSecret {
	page := os.Getpagesize()
	if n > page {
		noterNonVerrouille(errPhraseTropLongue)
		return &tamponSecret{octets: make([]byte, n)}
	}
	support := make([]byte, 2*page)
	reste := int(uintptr(unsafe.Pointer(&support[0])) % uintptr(page))
	debut := (page - reste) % page
	octets := support[debut : debut+page : debut+page]
	if err := verrouillerMemoire(octets); err != nil {
		noterNonVerrouille(err)
		return &tamponSecret{octets: make([]byte, n)}
	}
	return &tamponSecret{support: support, octets: octets, verrouille: true}
}

// liberer met le tampon à zéro, puis le déverrouille. Sans effet sur nil.
func (t *tamponSecret) liberer() {
	if t == nil {
		return
	}
	zero(t.octets)
	if t.verrouille {
		// Un échec ne laisse qu'une page verrouillée, déjà à zéro, jusqu'à
		// la fin du processus : rien à faire de plus.
		_ = deverrouillerMemoire(t.octets)
		t.verrouille = false
	}
}

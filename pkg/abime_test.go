package pkg

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/minio/sio"
)

// TestFichierAbime : seules les erreurs d'un fichier abîmé, ou qui n'est pas
// un .chto, sont reconnues — en-tête inconnu, en-tête tronqué, contenu qui ne
// s'authentifie pas —, même enveloppées. Une mauvaise phrase ou un droit
// refusé ne le sont pas : l'interface leur donne un autre conseil.
func TestFichierAbime(t *testing.T) {
	cas := []struct {
		nom     string
		err     error
		attendu bool
	}{
		{"format inconnu", fmt.Errorf("lecture: %w", errBadMagic), true},
		{"en-tête tronqué", errTruncated, true},
		{"charge utile absente", fmt.Errorf("%w : la charge utile est absente", errTruncated), true},
		{"contenu non authentifié", fmt.Errorf("déchiffrement: %w", sio.Error{}), true},
		{"mauvaise phrase", ErrBadPassword, false},
		{"permission refusée", &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}, false},
		{"autre", errors.New("disque plein"), false},
		{"nil", nil, false},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := FichierAbime(c.err); got != c.attendu {
				t.Errorf("FichierAbime(%v) = %v, attendu %v", c.err, got, c.attendu)
			}
		})
	}
}

// TestContenuNonAuthentifie : seul un contenu qui ne s'authentifie pas est
// reconnu — l'erreur qu'une mauvaise phrase donne aussi sur un fichier
// d'avant l'engagement de clé.
func TestContenuNonAuthentifie(t *testing.T) {
	if !ContenuNonAuthentifie(fmt.Errorf("déchiffrement: %w", sio.Error{})) {
		t.Error("une erreur sio n'est pas reconnue")
	}
	if ContenuNonAuthentifie(errBadMagic) || ContenuNonAuthentifie(nil) {
		t.Error("une erreur d'en-tête est prise pour un contenu non authentifié")
	}
}

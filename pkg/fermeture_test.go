package pkg

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Tests de FermerTemporaires : le nettoyage définitif qui précède la sortie
// du processus (Ctrl+C, signal). Après lui, l'opération encore en cours dans
// sa goroutine ne doit plus rien laisser sur le disque.

// fermerPourLeTest ferme les temporaires et les rouvre à la fin du test : les
// autres tests du paquet tournent dans le même processus.
func fermerPourLeTest(t *testing.T) {
	t.Helper()
	FermerTemporaires()
	t.Cleanup(rouvrirTemporaires)
}

// sansTemporaire échoue s'il reste un .chto-tmp-* dans dossier.
func sansTemporaire(t *testing.T, dossier string) {
	t.Helper()
	restes, err := filepath.Glob(filepath.Join(dossier, ".chto-tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(restes) > 0 {
		t.Errorf("temporaires restés après FermerTemporaires : %v", restes)
	}
}

// TestFermerTemporairesRefuseLesNouveaux : une sortie (fichier ou dossier)
// créée après la fermeture est refusée avec errNettoye, sans rien laisser.
// C'est la fenêtre du déchiffrement dont Argon2 finit après Ctrl+C.
func TestFermerTemporairesRefuseLesNouveaux(t *testing.T) {
	dir := t.TempDir()
	fermerPourLeTest(t)

	if _, err := newAtomicFile(filepath.Join(dir, "cible"), false); !errors.Is(err, errNettoye) {
		t.Errorf("newAtomicFile après fermeture = %v, attendu errNettoye", err)
	}
	if _, err := newAtomicDir(filepath.Join(dir, "extrait")); !errors.Is(err, errNettoye) {
		t.Errorf("newAtomicDir après fermeture = %v, attendu errNettoye", err)
	}
	sansTemporaire(t, dir)
}

// TestFermerTemporairesSupprimeCeQuiArrive : un temporaire enregistré après la
// fermeture (la sauvegarde d'en-tête de passwd) est supprimé aussitôt.
func TestFermerTemporairesSupprimeCeQuiArrive(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), ".chto-tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	fermerPourLeTest(t)

	if err := trackTempFile(f.Name(), f); !errors.Is(err, errNettoye) {
		t.Errorf("trackTempFile après fermeture = %v, attendu errNettoye", err)
	}
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Error("le temporaire enregistré après la fermeture existe encore")
	}
}

// fermeEnRoute rend les octets d'une archive et appelle FermerTemporaires
// une fois `apres` octets lus : l'extraction est alors en plein milieu,
// comme sous un Ctrl+C.
type fermeEnRoute struct {
	r     io.Reader
	lus   int
	apres int
	once  sync.Once
}

func (f *fermeEnRoute) Read(p []byte) (int, error) {
	if f.lus >= f.apres {
		f.once.Do(FermerTemporaires)
	}
	// Lectures courtes : la fermeture tombe entre deux entrées, pas après
	// que tout a été lu d'un coup.
	if len(p) > 512 {
		p = p[:512]
	}
	n, err := f.r.Read(p)
	f.lus += n
	return n, err
}

// TestExtractionInterrompueNeLaisseRien : FermerTemporaires au milieu d'une
// extraction de dossier. L'extraction recrée les dossiers parents à chaque
// entrée : sans garde, elle refaisait le dossier temporaire supprimé et y
// écrivait du clair, que rien ne nettoyait plus avant la sortie du processus.
func TestExtractionInterrompueNeLaisseRien(t *testing.T) {
	work := t.TempDir()
	dest := filepath.Join(work, "extrait")
	out, err := newAtomicDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rouvrirTemporaires)

	archive := tarDePetitsFichiers(t, 200)
	src := &fermeEnRoute{r: bytes.NewReader(archive), apres: len(archive) / 3}
	if err := extractArchive(src, out.path); !errors.Is(err, errNettoye) {
		t.Errorf("extraction après fermeture = %v, attendu errNettoye", err)
	}
	// out.cleanup n'est volontairement pas appelé : le processus sort
	// avant que le defer de DecryptTo ait tourné.
	sansTemporaire(t, work)
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Errorf("la destination existe (Lstat : %v)", err)
	}
}

// TestDechiffrementApresFermetureNeLaisseRien : Argon2 finit après la
// fermeture ; la sortie, créée trop tard, est refusée et rien n'est écrit.
func TestDechiffrementApresFermetureNeLaisseRien(t *testing.T) {
	work := t.TempDir()
	clair := filepath.Join(work, "clair.txt")
	if err := os.WriteFile(clair, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	chiffre := filepath.Join(work, "clair.txt.chto")
	if err := Encrypt(clair, chiffre, []byte("pw"), Options{}); err != nil {
		t.Fatal(err)
	}
	sortie := filepath.Join(work, "sortie.txt")
	fermerPourLeTest(t)

	if _, err := DecryptTo(chiffre, sortie, []byte("pw"), Options{}); !errors.Is(err, errNettoye) {
		t.Errorf("déchiffrement après fermeture = %v, attendu errNettoye", err)
	}
	sansTemporaire(t, work)
	if _, err := os.Lstat(sortie); !os.IsNotExist(err) {
		t.Errorf("la sortie existe (Lstat : %v)", err)
	}
}

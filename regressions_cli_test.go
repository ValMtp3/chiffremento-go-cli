package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chiffremento-cli/pkg"
)

// TestRefusEcrasementCLI : jusqu'ici, `-mode dec` remplaçait la destination en
// silence. Le refus est le défaut, -force le seul moyen de passer outre.
func TestRefusEcrasementCLI(t *testing.T) {
	dir := t.TempDir()
	contenu := []byte("le clair d'origine\n")
	in := ecrire(t, filepath.Join(dir, "doc.txt"), contenu)
	chto := in + extension

	avecMotDePasse(t, motDePasseTest)
	if err := doEncrypt(in, chto, pkg.Options{Algo: pkg.AlgoAES}); err != nil {
		t.Fatalf("chiffrement: %v", err)
	}

	// Le .chto existe déjà : un second chiffrement doit être refusé.
	avecMotDePasse(t, motDePasseTest)
	err := doEncrypt(in, chto, pkg.Options{Algo: pkg.AlgoAES})
	if err == nil {
		t.Error("le .chto existant a été écrasé sans -force")
	} else if !strings.Contains(err.Error(), "force") {
		t.Errorf("le message devrait mentionner -force: %v", err)
	}

	// La destination du déchiffrement est occupée par un fichier sans rapport.
	precieux := []byte("A NE PAS PERDRE\n")
	cible := ecrire(t, filepath.Join(dir, "cible.txt"), precieux)

	avecMotDePasse(t, motDePasseTest)
	if err := doDecrypt(chto, cible, false); err == nil {
		t.Error("la destination existante a été écrasée sans -force")
	}
	if b, _ := os.ReadFile(cible); !bytes.Equal(b, precieux) {
		t.Fatalf("le fichier a été touché malgré le refus: %q", b)
	}

	// Avec -force, l'écrasement est un choix assumé.
	avecMotDePasse(t, motDePasseTest)
	if err := doDecrypt(chto, cible, true); err != nil {
		t.Fatalf("-force devrait autoriser l'écrasement: %v", err)
	}
	if b, _ := os.ReadFile(cible); !bytes.Equal(b, contenu) {
		t.Errorf("-force n'a pas écrasé: %q", b)
	}
}

// TestOpenDestRefuseFichierExistant : le chemin des flux n'a pas d'écriture
// atomique — os.Create tronque la cible avant tout. Le refus doit donc aussi
// valoir ici, où il n'y a aucun retour en arrière possible.
func TestOpenDestRefuseFichierExistant(t *testing.T) {
	dir := t.TempDir()
	dest := ecrire(t, filepath.Join(dir, "occupe.bin"), []byte("contenu existant"))

	if _, _, err := openDest(dest, false); err == nil {
		t.Error("openDest a tronqué un fichier existant sans -force")
	}
	if b, _ := os.ReadFile(dest); string(b) != "contenu existant" {
		t.Errorf("le fichier a été tronqué malgré le refus: %q", b)
	}

	w, closeDst, err := openDest(dest, true)
	if err != nil {
		t.Fatalf("-force devrait autoriser: %v", err)
	}
	if _, err := w.Write([]byte("neuf")); err != nil {
		t.Fatal(err)
	}
	if err := closeDst(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "neuf" {
		t.Errorf("écriture attendue, obtenu %q", b)
	}

	// La sortie standard n'est jamais concernée par le contrôle.
	if _, _, err := openDest("-", false); err != nil {
		t.Errorf("la sortie standard ne devrait pas être contrôlée: %v", err)
	}
}

// TestConfirmerEcrasementDossier : la TUI peut poser la question pour un
// fichier, jamais pour un dossier — accepter reviendrait à supprimer une
// arborescence entière sur un « oui ».
func TestConfirmerEcrasementDossier(t *testing.T) {
	dir := t.TempDir()

	// Rien à cet emplacement : aucune question, aucune erreur.
	if err := confirmerEcrasement(filepath.Join(dir, "absent")); err != nil {
		t.Errorf("une destination libre ne devrait rien déclencher: %v", err)
	}

	existant := filepath.Join(dir, "sous-dossier")
	if err := os.Mkdir(existant, 0o755); err != nil {
		t.Fatal(err)
	}
	err := confirmerEcrasement(existant)
	if err == nil {
		t.Fatal("un dossier existant devrait être refusé sans question")
	}
	if !strings.Contains(err.Error(), "dossier") {
		t.Errorf("le message devrait dire qu'il s'agit d'un dossier: %v", err)
	}
}

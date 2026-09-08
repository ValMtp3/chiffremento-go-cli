package pkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Régressions : chacun de ces tests correspond à un bug qui a existé, et qui
// passait silencieusement — c'est précisément pour ça qu'ils sont ici.

// TestDossierLienSymboliqueRefuse : chiffrer un lien symbolique vers un dossier
// produisait une archive *vide*, sans erreur. os.Stat suivait le lien et voyait
// un dossier, puis WalkDir s'arrêtait dessus sans y descendre. Le déchiffrement
// rendait alors un dossier vide — le pire des cas pour une sauvegarde, où l'on
// croit avoir restauré et où il n'y a rien.
func TestDossierLienSymboliqueRefuse(t *testing.T) {
	dir := t.TempDir()
	reel := filepath.Join(dir, "reel")
	if err := os.MkdirAll(reel, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reel, "a.txt"), []byte("contenu"), 0o644); err != nil {
		t.Fatal(err)
	}
	lien := filepath.Join(dir, "lien")
	if err := os.Symlink(reel, lien); err != nil {
		t.Skip("liens symboliques indisponibles ici:", err)
	}

	err := Encrypt(lien, filepath.Join(dir, "out.chto"), []byte("motdepasse"), Options{})
	if err == nil {
		t.Fatal("un lien symbolique vers un dossier a été accepté : l'archive produite serait vide")
	}
	// Le message doit orienter vers la cible du lien, sinon l'utilisateur ne
	// sait pas quoi faire de ce refus.
	if !strings.Contains(err.Error(), "lien") {
		t.Errorf("message peu explicite: %v", err)
	}
}

// TestDestinationExistanteRefusee : le rename final d'atomicFile remplaçait la
// destination sans rien demander. Déchiffrer `doc.pdf.chto` à côté d'un
// `doc.pdf` sans rapport détruisait ce dernier — exactement le scénario que
// l'écriture atomique était censée écarter.
func TestDestinationExistanteRefusee(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "doc.txt")
	if err := os.WriteFile(src, []byte("le clair"), 0o644); err != nil {
		t.Fatal(err)
	}
	chto := src + ".chto"
	if err := Encrypt(src, chto, []byte("motdepasse"), Options{}); err != nil {
		t.Fatal(err)
	}

	// Chiffrement : le .chto existe déjà.
	if err := Encrypt(src, chto, []byte("motdepasse"), Options{}); err == nil {
		t.Error("un .chto existant a été écrasé sans -force")
	}

	// Déchiffrement : un fichier précieux occupe la destination.
	precieux := []byte("a ne pas perdre")
	if err := os.WriteFile(src, precieux, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(chto, src, []byte("motdepasse"), Options{}); err == nil {
		t.Error("la destination existante a été écrasée sans -force")
	}
	if b, _ := os.ReadFile(src); string(b) != string(precieux) {
		t.Fatalf("le fichier a été touché malgré le refus: %q", b)
	}

	// Force reste possible : c'est un choix explicite, pas un défaut.
	if err := Decrypt(chto, src, []byte("motdepasse"), Options{Force: true}); err != nil {
		t.Fatalf("Force devrait autoriser l'écrasement: %v", err)
	}
	if b, _ := os.ReadFile(src); string(b) != "le clair" {
		t.Errorf("Force n'a pas écrasé: %q", b)
	}
}

// TestDrapeauMetadataRefuseAvantV3 : le drapeau de remplissage était borné à la
// v3, celui des métadonnées non. Un fichier v1 ou v2 l'annonçant aurait vu ses
// premiers octets de clair relus comme un bloc de métadonnées.
func TestDrapeauMetadataRefuseAvantV3(t *testing.T) {
	for _, v := range []byte{versionV1, versionV2} {
		h := &header{
			Version: v,
			Flags:   FlagMetadata,
			Algo:    AlgoAES,
			Argon:   defaultArgonParams(),
			Salt:    make([]byte, saltSize),
		}
		if err := h.finalize(); err == nil {
			t.Errorf("FlagMetadata accepté sur un fichier v%d", v)
		}
	}
	// Sur un fichier v3, il reste évidemment légitime.
	h := &header{
		Version: versionV3,
		Flags:   FlagMetadata,
		Algo:    AlgoAES,
		Argon:   defaultArgonParams(),
		Salt:    make([]byte, saltSize),
	}
	if err := h.finalize(); err != nil {
		t.Errorf("FlagMetadata refusé à tort sur un fichier v3: %v", err)
	}
}

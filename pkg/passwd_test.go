package pkg

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Tests du changement de mot de passe. La promesse est double : le nouveau mot
// de passe ouvre le fichier, et le corps n'a pas été retouché — c'est tout
// l'intérêt de l'enveloppe, sinon autant re-chiffrer.

func TestChangePassword(t *testing.T) {
	contenu := bytes.Repeat([]byte("secret professionnel "), 400)
	chto := chiffreV4(t, contenu, Options{Algo: AlgoAES})

	avant, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}

	const nouveau = "un-nouveau-mot-de-passe"
	if err := ChangePassword(chto, []byte(motDePasseV4), []byte(nouveau)); err != nil {
		t.Fatalf("changement de mot de passe: %v", err)
	}

	apres, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}
	if len(avant) != len(apres) {
		t.Errorf("taille passée de %d à %d octets : le corps a été réécrit", len(avant), len(apres))
	}
	// Le corps ne bouge pas d'un octet : seul l'en-tête est réécrit.
	if !bytes.Equal(avant[headerSizeV4:], apres[headerSizeV4:]) {
		t.Error("le corps du fichier a changé : la clé de contenu n'a pas été conservée")
	}
	if bytes.Equal(avant[:headerSizeV4], apres[:headerSizeV4]) {
		t.Error("l'en-tête est identique : le sel et l'enveloppe auraient dû changer")
	}

	// Le nouveau mot de passe ouvre.
	out := filepath.Join(t.TempDir(), "clair.bin")
	if err := Decrypt(chto, out, []byte(nouveau), Options{}); err != nil {
		t.Fatalf("déchiffrement avec le nouveau mot de passe: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, contenu) {
		t.Error("contenu altéré par le changement de mot de passe")
	}

	// L'ancien n'ouvre plus.
	if err := Decrypt(chto, filepath.Join(t.TempDir(), "x.bin"), []byte(motDePasseV4), Options{}); !errors.Is(err, ErrBadPassword) {
		t.Errorf("l'ancien mot de passe donne %v, attendu ErrBadPassword", err)
	}
}

// TestChangePasswordMauvaisAncien : le fichier ne doit pas être touché d'un
// seul octet quand l'ancien mot de passe est faux. Une erreur ici détruirait un
// fichier dont on possède pourtant la clé.
func TestChangePasswordMauvaisAncien(t *testing.T) {
	chto := chiffreV4(t, []byte("contenu"), Options{})
	avant, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}

	err = ChangePassword(chto, []byte("mauvais"), []byte("peu-importe"))
	if !errors.Is(err, ErrBadPassword) {
		t.Errorf("erreur %v, attendu ErrBadPassword", err)
	}

	apres, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(avant, apres) {
		t.Error("le fichier a été modifié malgré un mot de passe refusé")
	}
}

// TestChangePasswordAnciensFormats : un fichier v1, v2 ou v3 n'a pas
// d'enveloppe — sa clé de contenu vient directement du mot de passe. Le refus
// doit être explicite et dire quoi faire.
func TestChangePasswordAnciensFormats(t *testing.T) {
	src := filepath.Join("testdata", "v2_aes.chto")
	copie := filepath.Join(t.TempDir(), "v2.chto")
	octets, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copie, octets, 0600); err != nil {
		t.Fatal(err)
	}

	err = ChangePassword(copie, []byte("reference-v2-password"), []byte("nouveau"))
	if err == nil {
		t.Fatal("un fichier v2 a accepté un changement de mot de passe")
	}
	if !strContains(err.Error(), "v4") {
		t.Errorf("message peu utile : %v", err)
	}

	apres, err := os.ReadFile(copie)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(octets, apres) {
		t.Error("le fichier v2 a été modifié")
	}
}

// TestChangePasswordEnchaine : plusieurs changements de suite, pour vérifier
// qu'aucun état ne traîne d'un appel à l'autre.
func TestChangePasswordEnchaine(t *testing.T) {
	contenu := []byte("contenu stable")
	chto := chiffreV4(t, contenu, Options{Algo: AlgoCascade})

	precedent := motDePasseV4
	for _, mdp := range []string{"deuxieme-mot-de-passe", "troisieme-mot-de-passe", "quatrieme"} {
		if err := ChangePassword(chto, []byte(precedent), []byte(mdp)); err != nil {
			t.Fatalf("changement vers %q: %v", mdp, err)
		}
		precedent = mdp
	}

	out := filepath.Join(t.TempDir(), "clair.bin")
	if err := Decrypt(chto, out, []byte(precedent), Options{}); err != nil {
		t.Fatalf("déchiffrement après trois changements: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, contenu) {
		t.Error("contenu altéré après plusieurs changements")
	}
}

func strContains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

// TestChangePasswordSauvegardeEntete : l'ancien en-tête est mis de côté le temps
// du remplacement, et disparaît une fois le nouveau écrit. S'il traînait, le
// changement suivant serait refusé pour rien.
func TestChangePasswordSauvegardeEntete(t *testing.T) {
	chto := chiffreV4(t, []byte("contenu"), Options{})
	sauvegarde := chto + suffixeSauvegarde

	if err := ChangePassword(chto, []byte(motDePasseV4), []byte("nouveau-mot-de-passe")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sauvegarde); err == nil {
		t.Error("la sauvegarde de l'en-tête est restée après un changement réussi")
	}
}

// TestChangePasswordSauvegardePresente : une sauvegarde déjà là veut dire qu'un
// changement est en cours ailleurs, ou qu'un précédent a été interrompu. Dans
// les deux cas, écraser serait le pire choix — celui qui perdrait le seul
// en-tête encore valide.
func TestChangePasswordSauvegardePresente(t *testing.T) {
	chto := chiffreV4(t, []byte("contenu"), Options{})
	sauvegarde := chto + suffixeSauvegarde
	if err := os.WriteFile(sauvegarde, []byte("en-tête d'un autre passage"), 0600); err != nil {
		t.Fatal(err)
	}
	avant, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}

	err = ChangePassword(chto, []byte(motDePasseV4), []byte("nouveau-mot-de-passe"))
	if err == nil {
		t.Fatal("le changement a été accepté malgré une sauvegarde en place")
	}
	if !strContains(err.Error(), suffixeSauvegarde) {
		t.Errorf("le message ne nomme pas la sauvegarde: %v", err)
	}

	apres, err := os.ReadFile(chto)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(avant, apres) {
		t.Error("le fichier a été modifié alors que le changement était refusé")
	}
	// La sauvegarde de l'autre passage doit être intacte.
	garde, err := os.ReadFile(sauvegarde)
	if err != nil {
		t.Fatal(err)
	}
	if string(garde) != "en-tête d'un autre passage" {
		t.Error("la sauvegarde existante a été écrasée")
	}
}

// TestMarshalScelleIgnoreLEnveloppe : les données authentifiées ne doivent pas
// dépendre de l'état du champ Wrapped au moment de l'appel — avant scellement,
// il est vide ; après, il est plein, et l'AAD doit rester la même.
func TestMarshalScelleIgnoreLEnveloppe(t *testing.T) {
	h := &header{
		Version: versionV4,
		Algo:    AlgoAES,
		Argon:   defaultArgonParams(),
		Salt:    bytes.Repeat([]byte{7}, saltSize),
		Commit:  bytes.Repeat([]byte{9}, commitSize),
	}
	avant := h.marshalScelle()

	h.Wrapped = bytes.Repeat([]byte{1}, wrappedSize)
	apres := h.marshalScelle()

	if !bytes.Equal(avant, apres) {
		t.Error("les données authentifiées changent selon que l'enveloppe est posée ou non")
	}
	if len(avant) != headerSizeV4-wrappedSize {
		t.Errorf("données authentifiées de %d octets, attendu %d", len(avant), headerSizeV4-wrappedSize)
	}
}

// TestChangePasswordEntreesInvalides : les refus élémentaires, qui doivent tous
// tomber avant la moindre écriture.
func TestChangePasswordEntreesInvalides(t *testing.T) {
	chto := chiffreV4(t, []byte("contenu"), Options{})

	if err := ChangePassword(chto, []byte(motDePasseV4), nil); err == nil {
		t.Error("un nouveau mot de passe vide a été accepté")
	}
	if err := ChangePassword(filepath.Join(t.TempDir(), "absent.chto"), []byte("a"), []byte("b")); err == nil {
		t.Error("un fichier inexistant a été accepté")
	}
	// Un fichier qui n'est pas un .chto : l'en-tête doit être refusé avant tout.
	pasUnChto := filepath.Join(t.TempDir(), "texte.chto")
	if err := os.WriteFile(pasUnChto, []byte("ceci n'est pas un en-tête"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ChangePassword(pasUnChto, []byte("a"), []byte("b")); err == nil {
		t.Error("un fichier sans en-tête valide a été accepté")
	}
}

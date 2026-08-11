package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// formulaire et huhForm ne servent qu'à porter le formulaire d'un appel à
// l'autre : Update renvoie un tea.Model, qu'il faut réaffecter.
type formulaire = huh.Form

type huhForm struct{ form *formulaire }

// TestFormulairesSeConstruisent vérifie que les deux formulaires se montent
// sans panique, thème appliqué, dans toutes les combinaisons d'opération et de
// mode de saisie.
func TestFormulairesSeConstruisent(t *testing.T) {
	action, mode := "enc", "saisie"
	if f := choixForm(&action, &mode); f == nil {
		t.Fatal("choixForm a renvoyé nil")
	}
	for _, a := range []string{"enc", "dec", "verify"} {
		for _, m := range []string{"saisie", "parcourir"} {
			path := ""
			if f := cibleForm(a, m, &path); f == nil {
				t.Fatalf("cibleForm(%q, %q) a renvoyé nil", a, m)
			}
		}
	}
	if f := filePickerField("enc", new(string)); f == nil {
		t.Fatal("filePickerField a renvoyé nil")
	}
	if th := formTheme(); th == nil {
		t.Fatal("formTheme a renvoyé nil")
	}
}

func TestValidateTarget(t *testing.T) {
	dir := t.TempDir()
	clair := filepath.Join(dir, "doc.txt")
	chiffre := filepath.Join(dir, "doc.txt.chto")
	for _, p := range []string{clair, chiffre} {
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name    string
		path    string
		action  string
		wantErr bool
	}{
		{"fichier clair à chiffrer", clair, "enc", false},
		{"fichier chiffré à déchiffrer", chiffre, "dec", false},
		{"déjà chiffré, on veut chiffrer", chiffre, "enc", true},
		{"pas de .chto, on veut déchiffrer", clair, "dec", true},
		{"fichier absent", filepath.Join(dir, "fantome.txt"), "enc", true},
		{"dossier à chiffrer", dir, "enc", false},
		{"dossier avec séparateur final", dir + string(os.PathSeparator), "enc", false},
		{"dossier à déchiffrer", dir, "dec", true},
		{"dossier à vérifier", dir, "verify", true},
		{"chemin vide", "", "enc", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateTarget(c.path, c.action)
			if (err != nil) != c.wantErr {
				t.Errorf("validateTarget(%q, %q) = %v, erreur attendue: %v", c.path, c.action, err, c.wantErr)
			}
		})
	}
}

// TestTrimTrailingSeparator : un dossier glissé dans le terminal arrive souvent
// avec un séparateur final, qui donnerait une sortie nommée « photos/.chto ».
func TestTrimTrailingSeparator(t *testing.T) {
	sep := string(os.PathSeparator)
	cases := []struct{ in, want string }{
		{"photos" + sep, "photos"},
		{"photos" + sep + sep, "photos"},
		{sep + "tmp" + sep + "a" + sep, sep + "tmp" + sep + "a"},
		{"photos", "photos"},
		{sep, sep},
	}
	for _, c := range cases {
		if got := trimTrailingSeparator(c.in); got != c.want {
			t.Errorf("trimTrailingSeparator(%q) = %q, attendu %q", c.in, got, c.want)
		}
	}
}

// TestIndicateurDeForceDictionnaire : le cas qui échappait à l'estimation
// combinatoire de la v2.0. « azerty123 » y passait pour un mot de passe à ~60
// bits, donc « correct » ; zxcvbn le reconnaît comme une suite de touches
// suivie d'un compteur.
func TestIndicateurDeForceDictionnaire(t *testing.T) {
	faibles := []string{"azerty123", "password1", "motdepasse", "Bonjour2024!", "aaaaaaaaaaaa", "p@ssw0rd"}
	for _, pw := range faibles {
		bits := passwordEntropy(pw)
		if bits >= bitsFaible {
			t.Errorf("%q évalué à %.0f bits, attendu moins de %d", pw, bits, bitsFaible)
		}
		if !strings.Contains(strengthHint(pw), "faible") {
			t.Errorf("%q n'est pas annoncé comme faible: %s", pw, strengthHint(pw))
		}
	}

	solides := []string{"tR7#vq2Lm!9zXw4Ke", "girafe-clavier-nuage-71-tempete"}
	for _, pw := range solides {
		bits := passwordEntropy(pw)
		if bits < bitsCorrect {
			t.Errorf("%q évalué à %.0f bits, attendu au moins %d", pw, bits, bitsCorrect)
		}
	}

	// À longueur égale, une saisie qui suit un motif connu doit être notée sous
	// une saisie aléatoire : c'est tout l'apport du dictionnaire.
	if passwordEntropy("azertyuiopqs") >= passwordEntropy("x7Qv2mKp9Lzt") {
		t.Error("un motif de clavier est évalué aussi haut qu'une saisie aléatoire de même longueur")
	}
}

func TestStrengthHintVide(t *testing.T) {
	if got := strengthHint(""); !strings.Contains(got, "jamais affiché") {
		t.Errorf("aide inattendue pour une saisie vide: %q", got)
	}
	if bits := passwordEntropy(""); bits != 0 {
		t.Errorf("passwordEntropy(\"\") = %v, attendu 0", bits)
	}
}

func TestChooseAlgo(t *testing.T) {
	if _, err := chooseAlgo(true, true); err == nil {
		t.Error("-chacha et -parano combinés devraient être refusés")
	}
	for _, c := range []struct {
		chacha, parano bool
		want           byte
	}{
		{false, false, 1}, // aes
		{true, false, 2},  // chacha
		{false, true, 3},  // cascade
	} {
		got, err := chooseAlgo(c.chacha, c.parano)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("chooseAlgo(%v, %v) = %d, attendu %d", c.chacha, c.parano, got, c.want)
		}
	}
}

func TestCheckPaths(t *testing.T) {
	if err := checkPaths("a.txt", "a.txt"); err == nil {
		t.Error("une source identique à la destination devrait être refusée")
	}
	if err := checkPaths("./a.txt", "a.txt"); err == nil {
		t.Error("les chemins équivalents devraient être détectés")
	}
	if err := checkPaths("a.txt", "a.txt.chto"); err != nil {
		t.Errorf("chemins distincts refusés à tort: %v", err)
	}
}

// --- Pilotage des formulaires -------------------------------------------

// huh.Form est un modèle Bubble Tea : on peut donc lui envoyer des touches et
// lire son rendu sans terminal. C'est ce qui permet de vérifier que
// l'explorateur de fichiers apparaît réellement, et ouvert — la seule chose
// qu'un test de construction ne dit pas.

// envoyer applique une touche au formulaire et déroule les commandes qu'il
// renvoie, comme le ferait la boucle de Bubble Tea.
func envoyer(t *testing.T, f *huhForm, msg tea.Msg) {
	t.Helper()
	modele, cmd := f.form.Update(msg)
	f.form = modele.(*formulaire)
	deroule(t, f, cmd, 0)
}

// deroule exécute une commande et réinjecte le message produit. La profondeur
// est bornée : une commande qui se relancerait indéfiniment ferait tourner le
// test sans fin plutôt que d'échouer.
func deroule(t *testing.T, f *huhForm, cmd tea.Cmd, profondeur int) {
	t.Helper()
	if cmd == nil || profondeur > 20 {
		return
	}
	msg := cmd()
	switch m := msg.(type) {
	case nil:
		return
	case tea.BatchMsg:
		for _, c := range m {
			deroule(t, f, c, profondeur+1)
		}
		return
	case tea.QuitMsg:
		return
	}
	modele, suivante := f.form.Update(msg)
	f.form = modele.(*formulaire)
	deroule(t, f, suivante, profondeur+1)
}

func ouvrir(t *testing.T, form *formulaire) *huhForm {
	t.Helper()
	f := &huhForm{form: form}
	deroule(t, f, f.form.Init(), 0)
	return f
}

// TestChoixFormAfficheLesDeuxQuestions : l'opération, puis le mode de saisie.
func TestChoixFormAfficheLesDeuxQuestions(t *testing.T) {
	action, mode := "enc", "saisie"
	f := ouvrir(t, choixForm(&action, &mode))

	vue := f.form.View()
	if !strings.Contains(vue, "opération") {
		t.Errorf("la question de l'opération manque:\n%s", vue)
	}
	if !strings.Contains(vue, "désigner la cible") {
		t.Errorf("le choix du mode de désignation manque:\n%s", vue)
	}

	// La bascule au clavier doit écrire dans la variable liée.
	envoyer(t, f, tea.KeyMsg{Type: tea.KeyEnter}) // opération validée
	envoyer(t, f, tea.KeyMsg{Type: tea.KeyDown})  // « parcourir »
	if mode != "parcourir" {
		t.Errorf("mode = %q après une flèche bas, attendu parcourir", mode)
	}
}

// TestCibleFormExplorateurOuvert est le test de la correction : l'explorateur
// doit s'afficher déployé, sans permissions, sans qu'aucune touche soit
// nécessaire pour le déplier.
func TestCibleFormExplorateurOuvert(t *testing.T) {
	path := ""
	f := ouvrir(t, cibleForm("enc", "parcourir", &path))

	vue := f.form.View()
	if !strings.Contains(vue, "entrer dans un dossier") {
		t.Errorf("l'explorateur n'est pas affiché:\n%s", vue)
	}
	// « No file selected. » signifie que huh attend une touche avant de montrer
	// l'arborescence : c'est précisément ce qu'on ne veut plus.
	if strings.Contains(vue, "No file selected") {
		t.Errorf("l'explorateur est replié, il faut une touche pour l'ouvrir:\n%s", vue)
	}
	if strings.Contains(vue, "drwx") || strings.Contains(vue, "-rw-") {
		t.Errorf("les permissions encombrent la liste:\n%s", vue)
	}
	if strings.Contains(vue, "glisser") {
		t.Errorf("le champ texte est affiché alors que le mode est parcourir:\n%s", vue)
	}
}

func TestCibleFormChampTexte(t *testing.T) {
	path := ""
	f := ouvrir(t, cibleForm("enc", "saisie", &path))

	vue := f.form.View()
	if !strings.Contains(vue, "glisser") {
		t.Errorf("le champ texte n'est pas affiché:\n%s", vue)
	}
	if strings.Contains(vue, "entrer dans un dossier") {
		t.Errorf("l'explorateur est affiché alors que le mode est saisie:\n%s", vue)
	}
}

// TestCibleFormAnnonceLaCibleAttendue : au déchiffrement, seul un .chto a un
// sens — le champ doit le dire, et les deux chemins de saisie doivent le dire
// pareil.
func TestCibleFormAnnonceLaCibleAttendue(t *testing.T) {
	for _, mode := range []string{"saisie", "parcourir"} {
		for _, action := range []string{"dec", "verify"} {
			path := ""
			f := ouvrir(t, cibleForm(action, mode, &path))
			if vue := f.form.View(); !strings.Contains(vue, extension) {
				t.Errorf("%s/%s : le champ ne nomme pas l'extension attendue:\n%s", action, mode, vue)
			}
		}
		path := ""
		f := ouvrir(t, cibleForm("enc", mode, &path))
		if vue := f.form.View(); !strings.Contains(vue, "dossier") {
			t.Errorf("enc/%s : le champ ne mentionne pas le dossier:\n%s", mode, vue)
		}
	}
}

// TestCibleFormExplorateurListeAssezDEntrees garde le piège de l'ordre des
// appels : si Height est appelé après Title, huh réduit la liste à une seule
// ligne et l'explorateur devient inutilisable — sans que rien ne plante.
func TestCibleFormExplorateurListeAssezDEntrees(t *testing.T) {
	dir := t.TempDir()
	// Un fichier caché dans le lot : ShowHidden doit être effectif, sinon on ne
	// pourrait pas chiffrer une clé dans ~/.ssh depuis l'explorateur.
	noms := []string{"alpha.txt", "beta.txt", "gamma.txt", "delta.txt",
		"epsilon.txt", "zeta.txt", "eta.txt", ".config_cache"}
	for _, n := range noms {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// L'explorateur démarre dans le dossier courant.
	precedent, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(precedent)

	path := ""
	f := ouvrir(t, cibleForm("enc", "parcourir", &path))
	vue := f.form.View()

	manquants := []string{}
	for _, n := range noms {
		if !strings.Contains(vue, n) {
			manquants = append(manquants, n)
		}
	}
	if len(manquants) > 0 {
		t.Errorf("%d entrées sur %d ne sont pas listées (%v) — la liste est probablement réduite à une ligne:\n%s",
			len(manquants), len(noms), manquants, vue)
	}
}

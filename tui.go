package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/trustelem/zxcvbn"
	"golang.org/x/term"
)

// isInteractive n'autorise la TUI que si les deux extrémités sont un
// terminal. Sinon on tomberait en marche dans un pipe ou un job de CI.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI enchaîne les formulaires puis l'écran de progression.
//
// Deux formulaires successifs et non un seul à groupes masqués : le second est
// donc construit *après* que l'opération et le mode de saisie sont connus. Ça
// évite tout un nid de guêpes — un champ dont la configuration dépend d'un choix
// pas encore fait, et un explorateur que huh replie dès qu'on tente de revenir
// en arrière, laissant l'utilisateur devant une liste disparue.
func runTUI() error {
	action := "enc"
	mode := "saisie"
	if err := choixForm(&action, &mode).Run(); err != nil {
		return err
	}

	path := ""
	if err := cibleForm(action, mode, &path).Run(); err != nil {
		return err
	}
	path = trimTrailingSeparator(strings.TrimSpace(expandHome(path)))

	switch action {
	case "dec":
		return tuiDecrypt(path)
	case "verify":
		return tuiVerify(path)
	default:
		return tuiEncrypt(path)
	}
}

// choixForm demande l'opération et la façon de désigner la cible.
func choixForm(action *string, mode *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Key("action").
				Title("opération").
				Options(
					huh.NewOption("chiffrer un fichier ou un dossier", "enc"),
					huh.NewOption("déchiffrer un "+extension+"  (fichier ou dossier)", "dec"),
					huh.NewOption("vérifier un "+extension+"  (sans rien écrire)", "verify"),
				).
				Value(action),

			huh.NewSelect[string]().
				Key("mode").
				Title("désigner la cible").
				Options(
					huh.NewOption("saisir un chemin  (ou glisser-déposer)", "saisie"),
					huh.NewOption("parcourir les fichiers", "parcourir"),
				).
				Value(mode),
		),
	).WithTheme(formTheme()).WithShowHelp(true)
}

// cibleForm demande la cible, au clavier ou en naviguant. L'opération est déjà
// connue : le champ peut donc s'annoncer précisément.
func cibleForm(action, mode string, path *string) *huh.Form {
	var champ huh.Field
	if mode == "parcourir" {
		champ = filePickerField(action, path)
	} else {
		champ = huh.NewInput().
			Key("path").
			Title(cibleTitre(action)).
			Placeholder(ciblePlaceholder(action)).
			Value(path).
			Validate(func(s string) error { return validateTarget(s, action) })
	}
	return huh.NewForm(huh.NewGroup(champ)).WithTheme(formTheme()).WithShowHelp(true)
}

// filePickerField construit l'explorateur. Il vient de huh, donc de bubbles :
// aucune dépendance nouvelle.
//
// Picking(true) est essentiel : sans lui, le champ affiche « No file selected. »
// et il faut appuyer sur une touche pour ouvrir l'arborescence. On veut la liste
// tout de suite — c'est la raison d'être du mode « parcourir ».
//
// Les permissions ne sont pas affichées : `drwxr-xr-x` n'aide personne à choisir
// un fichier et vole la place du nom. La taille, elle, sert. Les fichiers cachés
// sont visibles parce que c'est précisément le genre de fichier qu'on chiffre —
// une clé dans ~/.ssh, un fichier de configuration.
//
// Les dossiers ne sont sélectionnables qu'au chiffrement : ailleurs, seul un
// .chto a un sens. `validateTarget` reste l'autorité sur le reste, avec ses
// messages en français — `AllowedTypes` afficherait les siens en anglais et
// ferait exister deux règles là où il n'en faut qu'une.
func filePickerField(action string, path *string) huh.Field {
	// L'ordre des appels compte, et c'est un vrai piège de huh.
	//
	// NewFilePicker lit déjà le dossier à la construction. ShowHidden et Height
	// doivent donc venir en premier : posés plus loin dans la chaîne, le premier
	// n'a aucun effet — les fichiers cachés restent invisibles — et le second
	// soustrait la hauteur d'un titre rendu sans thème, ce qui ne laisse qu'une
	// seule ligne de liste. Dans les deux cas, rien ne plante : l'explorateur est
	// simplement inutilisable. TestCibleFormExplorateurListeAssezDEntrees garde
	// ces deux propriétés.
	//
	// Les fichiers cachés sont montrés parce que c'est précisément le genre de
	// fichier qu'on chiffre : une clé dans ~/.ssh, un fichier de configuration.
	return huh.NewFilePicker().
		ShowHidden(true).
		Height(16).
		Key("picker").
		Title(cibleTitre(action)).
		Description("↑↓ se déplacer · → entrer dans un dossier · entrée choisir").
		CurrentDirectory(".").
		// Picking : sans lui, le champ affiche « No file selected. » et il faut
		// appuyer sur une touche pour déplier l'arborescence. On veut la liste
		// tout de suite — c'est la raison d'être du mode « parcourir ».
		Picking(true).
		// Un dossier n'est une cible qu'au chiffrement ; ailleurs, seul un .chto
		// a un sens.
		DirAllowed(action == "enc").
		FileAllowed(true).
		// Les permissions ne sont pas affichées : `drwxr-xr-x` n'aide personne à
		// choisir un fichier et vole la place du nom. La taille, elle, sert.
		ShowSize(true).
		ShowPermissions(false).
		Value(path).
		// Une sélection vide ne bloque pas la navigation : sinon huh refuse de
		// quitter le champ tout en repliant la liste, et l'utilisateur se
		// retrouve devant un écran vide sans comprendre pourquoi. Le reste est
		// tranché par validateTarget, avec ses messages en français.
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return nil
			}
			return validateTarget(s, action)
		})
}

// cibleTitre nomme ce qu'on attend selon l'opération.
func cibleTitre(action string) string {
	if action == "enc" {
		return "fichier ou dossier à chiffrer"
	}
	return "fichier " + extension + " à lire"
}

func ciblePlaceholder(action string) string {
	if action == "enc" {
		return "chemin, ou glisser-déposer le fichier ou le dossier"
	}
	return "chemin du fichier " + extension + ", ou glisser-déposer"
}

// validateTarget refuse tout de suite les cas qui échoueraient plus loin :
// chemin absent, dossier là où seul un .chto a du sens, ou extension
// incohérente avec l'opération.
func validateTarget(s, action string) error {
	s = trimTrailingSeparator(strings.TrimSpace(expandHome(s)))
	if s == "" {
		return errors.New("indique un fichier ou un dossier")
	}
	info, err := os.Stat(s)
	if err != nil {
		return errors.New("chemin introuvable")
	}
	if info.IsDir() && action != "enc" {
		return errors.New("c'est un dossier : seul un fichier " + extension + " peut être déchiffré ou vérifié")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("ce n'est ni un fichier régulier ni un dossier")
	}
	if (action == "dec" || action == "verify") && !strings.HasSuffix(s, extension) {
		return errors.New("ce fichier doit porter l'extension " + extension)
	}
	if action == "enc" && strings.HasSuffix(s, extension) {
		return errors.New("ce fichier est déjà chiffré")
	}
	return nil
}

func tuiEncrypt(path string) error {
	algo := pkg.AlgoAES
	// Un dossier est presque toujours un mélange de texte, de code et de
	// métadonnées répétitives, et le tar ajoute lui-même beaucoup de zéros de
	// bourrage : la compression y gagne largement plus que sur un fichier
	// isolé. Elle est donc proposée déjà active — mais toujours refusable,
	// puisqu'elle laisse fuiter la compressibilité du contenu.
	estDossier := false
	if st, err := os.Stat(path); err == nil {
		estDossier = st.IsDir()
	}
	// zstd est le seul algorithme proposé : gzip n'est plus produit, seulement
	// relu pour les anciens fichiers. La question se réduit donc à « compresser
	// ou pas ».
	compresser := estDossier
	pad := false
	kdf := pkg.KDFStandard
	// Les métadonnées ne concernent qu'un fichier : l'archive tar d'un dossier
	// porte déjà noms, dates et permissions de chaque entrée.
	garderMeta := false
	password, confirm := "", ""

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[byte]().
				Title("algorithme").
				Options(
					huh.NewOption("aes-256-gcm  (défaut)", pkg.AlgoAES),
					huh.NewOption("chacha20-poly1305", pkg.AlgoChaCha),
					huh.NewOption("cascade  chacha20 + aes  (parano)", pkg.AlgoCascade),
				).
				Value(&algo),

			// La description montre la mémoire exigée, parce qu'elle le sera
			// aussi au déchiffrement : un fichier scellé en « maximum » ici sera
			// illisible sur une machine qui n'a pas 1 Gio à y consacrer.
			huh.NewSelect[pkg.KDFProfile]().
				Title("coût de la dérivation de clé").
				DescriptionFunc(func() string { return kdfHint(kdf) }, &kdf).
				Options(
					huh.NewOption("standard  (défaut)", pkg.KDFStandard),
					huh.NewOption("fort", pkg.KDFFort),
					huh.NewOption("maximum", pkg.KDFMaximum),
				).
				Value(&kdf),

			huh.NewConfirm().
				Title("compresser avant chiffrement  (zstd)").
				Description(compressHint(estDossier)).
				Affirmative("oui").
				Negative("non").
				Value(&compresser),
		),

		// Le masquage de taille vit dans son propre groupe, escamoté dès qu'une
		// compression est choisie : proposer une option pour la refuser ensuite
		// est une impasse, autant ne pas la montrer. Un groupe masqué est aussi
		// sauté à la navigation, donc l'utilisateur passe directement au mot de
		// passe.
		huh.NewGroup(
			huh.NewConfirm().
				Title("masquer la taille réelle").
				Description("arrondit la taille au palier supérieur (jusqu'à ~12 % de disque en plus)").
				Affirmative("oui").
				Negative("non").
				Value(&pad),
		).WithHideFunc(func() bool { return compresser }),

		huh.NewGroup(
			huh.NewConfirm().
				Title("conserver le nom et la date d'origine").
				Description("stockés à l'intérieur du chiffré, donc restituables même sous un nom neutre").
				Affirmative("oui").
				Negative("non").
				Value(&garderMeta),
		).WithHideFunc(func() bool { return estDossier }),

		huh.NewGroup(
			huh.NewInput().
				Title("mot de passe").
				// La description se recalcule à chaque frappe : l'utilisateur
				// voit la robustesse de son mot de passe pendant qu'il le tape.
				DescriptionFunc(func() string { return strengthHint(password) }, &password).
				EchoMode(huh.EchoModePassword).
				Value(&password).
				Validate(validatePassword),

			huh.NewInput().
				Title("confirmation").
				Description("une faute de frappe rendrait le fichier définitivement irrécupérable").
				EchoMode(huh.EchoModePassword).
				Value(&confirm).
				Validate(func(s string) error {
					if s != password {
						return errors.New("les deux saisies diffèrent")
					}
					return nil
				}),
		),
	).WithTheme(formTheme()).WithShowHelp(true)

	if err := form.Run(); err != nil {
		return err
	}

	out := path + extension
	// La ligne « sel » du cadre reste sur une seule ligne : les mentions
	// s'y ajoutent plutôt que de casser la mise en page.
	salt := "16 o aléatoires · en-tête lié à la clé"
	switch {
	case estDossier && pad:
		salt = "16 o aléatoires · dossier tar · taille masquée"
	case estDossier:
		salt = "16 o aléatoires · dossier empaqueté en tar"
	case pad:
		salt = "16 o aléatoires · taille réelle masquée"
	}
	info := jobInfo{
		Action:  "chiffrement",
		In:      path,
		Out:     out,
		AEAD:    pkg.AlgoName(algo),
		KDF:     pkg.DefaultKDFLabel(),
		Salt:    salt,
		Success: out,
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Encrypt(path, out, []byte(password), pkg.Options{
			Algo: algo, Comp: compEncodee(compresser), Pad: pad,
			KDF: kdf, Metadata: metaEncodee(garderMeta), Progress: p,
		})
	})
}

func tuiDecrypt(path string) error {
	// L'en-tête est lisible sans mot de passe : on affiche les vrais
	// paramètres du fichier avant de demander quoi que ce soit.
	d, err := pkg.Inspect(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", d.Version, d.Algo, d.KDF)
	if d.Compressed {
		details += " · compressé"
	}
	if d.Archive {
		details += "\ncontient un dossier : il sera extrait dans " +
			filepath.Base(strings.TrimSuffix(path, extension)) + string(os.PathSeparator) +
			", qui ne doit pas déjà exister"
	}
	if d.Version < 3 {
		details += fmt.Sprintf("\nformat v%d, plus ancien que celui produit aujourd'hui : lecture seule, il sera relu tel quel", d.Version)
	}

	password := ""
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			huh.NewInput().
				Title("mot de passe").
				EchoMode(huh.EchoModePassword).
				Value(&password).
				Validate(validatePassword),
		),
	).WithTheme(formTheme()).WithShowHelp(true)

	if err := form.Run(); err != nil {
		return err
	}

	out := strings.TrimSuffix(path, extension)
	info := jobInfo{
		Action:  "déchiffrement",
		In:      path,
		Out:     out,
		AEAD:    d.Algo,
		KDF:     d.KDF,
		Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
		Success: out,
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Decrypt(path, out, []byte(password), pkg.Options{Progress: p})
	})
}

func tuiVerify(path string) error {
	d, err := pkg.Inspect(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", d.Version, d.Algo, d.KDF)
	if d.Compressed {
		details += " · compressé"
	}
	if d.Archive {
		details += " · dossier"
	}
	details += "\nrien ne sera écrit sur le disque"

	password := ""
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			huh.NewInput().
				Title("mot de passe").
				EchoMode(huh.EchoModePassword).
				Value(&password).
				Validate(validatePassword),
		),
	).WithTheme(formTheme()).WithShowHelp(true)

	if err := form.Run(); err != nil {
		return err
	}

	info := jobInfo{
		Action:  "vérification",
		In:      path,
		Out:     "(rien, contrôle seul)",
		AEAD:    d.Algo,
		KDF:     d.KDF,
		Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
		Success: verifySucces(d.Archive),
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Verify(path, []byte(password), pkg.Options{Progress: p})
	})
}

// teaOptions est vide en production. Les tests s'en servent pour faire
// tourner l'écran sans terminal, et donc vérifier sa durée réelle.
var teaOptions []tea.ProgramOption

// runJob lance l'opération dans une goroutine et affiche l'écran animé.
func runJob(info jobInfo, op func(progress func(done, total int64)) error) error {
	if size, err := pkg.InputSize(info.In); err == nil {
		info.Size = size
	}

	var done atomic.Int64
	model := newProgressModel(info, &done)
	prog := tea.NewProgram(model, teaOptions...)

	// L'erreur passe par un canal plutôt que par une variable partagée : elle
	// est écrite par la goroutine de chiffrement et lue ici après coup.
	errCh := make(chan error, 1)
	go func() {
		err := op(func(d, _ int64) { done.Store(d) })
		errCh <- err
		prog.Send(doneMsg{err: err})
	}()

	if _, err := prog.Run(); err != nil {
		return err
	}
	if err := <-errCh; err != nil {
		return err
	}

	fmt.Printf("  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(info.Success))
	return nil
}

// --- Saisie du mot de passe hors TUI ------------------------------------

// readPassword récupère le mot de passe sans jamais le faire transiter par la
// ligne de commande : le flag -key de la v1 était visible dans `ps aux` pour
// tous les utilisateurs de la machine et finissait dans l'historique du shell.
//
// Trois chemins, dans cet ordre :
//
//   - stdinTaken (l'entrée standard porte les données, avec -in -) : le mot de
//     passe est demandé sur le terminal de contrôle, /dev/tty. Sans ce détour,
//     la première ligne des *données* serait lue comme mot de passe — un bug
//     silencieux qui chiffrerait le reste avec un secret involontaire.
//   - entrée standard qui n'est pas un terminal : on lit une ligne. C'est le
//     chemin des scripts, et il ne fuite ni dans ps ni dans les arguments :
//     echo 'motdepasse' | chiffremento -mode enc -in f
//   - terminal : saisie masquée.
func readPassword(confirm bool, stdinTaken bool) ([]byte, error) {
	if stdinTaken {
		return readPasswordFromTTY(confirm)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return nil, errors.New("aucun mot de passe reçu sur l'entrée standard")
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return nil, errors.New("mot de passe vide")
		}
		return []byte(pw), nil
	}

	password := ""
	field := huh.NewInput().
		Title("mot de passe").
		EchoMode(huh.EchoModePassword).
		Value(&password).
		Validate(validatePassword).
		WithTheme(formTheme())
	if err := field.Run(); err != nil {
		return nil, err
	}

	if confirm {
		second := ""
		check := huh.NewInput().
			Title("confirmation").
			EchoMode(huh.EchoModePassword).
			Value(&second).
			Validate(func(s string) error {
				if s != password {
					return errors.New("les deux saisies diffèrent")
				}
				return nil
			}).
			WithTheme(formTheme())
		if err := check.Run(); err != nil {
			return nil, err
		}
	}

	return []byte(password), nil
}

// readPasswordFromTTY demande le mot de passe au terminal de contrôle, l'entrée
// standard étant occupée par les données.
//
// huh n'est pas utilisable ici : il lit os.Stdin. On passe donc directement par
// term.ReadPassword sur /dev/tty, ce qui donne la même saisie masquée sans
// habillage.
func readPasswordFromTTY(confirm bool) ([]byte, error) {
	tty, err := os.OpenFile(ttyDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("l'entrée standard porte les données à chiffrer, "+
			"le mot de passe doit donc être saisi au terminal — introuvable ici (%w). "+
			"Utilise -in FICHIER plutôt que -in -", err)
	}
	defer tty.Close()

	if !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.New("le terminal de contrôle n'est pas utilisable pour une saisie masquée : " +
			"utilise -in FICHIER plutôt que -in -")
	}

	ask := func(prompt string) ([]byte, error) {
		fmt.Fprintf(tty, "%s ", styleDim.Render(prompt))
		pw, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return nil, fmt.Errorf("lecture du mot de passe: %w", err)
		}
		return pw, nil
	}

	password, err := ask("mot de passe :")
	if err != nil {
		return nil, err
	}
	if err := validatePassword(string(password)); err != nil {
		return nil, err
	}

	if confirm {
		second, err := ask("confirmation :")
		if err != nil {
			return nil, err
		}
		defer zero(second)
		if !bytes.Equal(password, second) {
			return nil, errors.New("les deux saisies diffèrent")
		}
	}
	return password, nil
}

func validatePassword(s string) error {
	if s == "" {
		return errors.New("le mot de passe ne peut pas être vide")
	}
	return nil
}

// Seuils de l'indicateur de force, en bits d'entropie estimée par zxcvbn.
//
// Ils sont calibrés sur une attaque *hors ligne* : l'attaquant a le fichier et
// calcule à son rythme. Argon2id à 256 MiB le limite à l'ordre de 10⁴
// tentatives par seconde même avec du matériel dédié, soit ~2¹³/s. À ce
// rythme, 35 bits tombent en une poignée de jours et 50 bits demandent des
// milliers d'années. D'où les deux paliers.
//
// Ces seuils sont bien plus bas que ceux de la v2.0 parce que la mesure a
// changé de nature : le compte combinatoire d'avant surestimait tout — il
// donnait 60 bits à « azerty123 » — là où zxcvbn compte le nombre réel de
// tentatives nécessaires.
const (
	bitsFaible  = 35
	bitsCorrect = 50

	// offlineGuessRate : hypothèse d'attaque, en tentatives par seconde.
	offlineGuessRate = 1e4
)

// passwordEntropy estime l'entropie en bits à partir du nombre de tentatives
// que zxcvbn juge nécessaires pour retrouver le mot de passe.
//
// zxcvbn ne compte pas les combinaisons possibles : il décompose la saisie en
// motifs (mots de dictionnaire, prénoms, dates, suites de touches, répétitions,
// l33t speak) et additionne le coût de chacun. C'est ce qui fait que
// « azerty123 » est désormais évalué à une vingtaine de bits au lieu d'une
// soixantaine. Ça reste un repère pour l'utilisateur, pas une garantie, et rien
// ne bloque la saisie.
func passwordEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	guesses := zxcvbn.PasswordStrength(s, nil).Guesses
	if guesses < 2 {
		return 0
	}
	return math.Log2(guesses)
}

// strengthHint traduit l'entropie en une ligne lisible, avec l'ordre de
// grandeur du temps qu'une attaque hors ligne y passerait.
func strengthHint(s string) string {
	if s == "" {
		return "jamais affiché, jamais visible dans ps ni dans l'historique"
	}
	bits := passwordEntropy(s)
	verdict := "solide"
	switch {
	case bits < bitsFaible:
		verdict = "faible, une phrase de passe serait bien plus sûre"
	case bits < bitsCorrect:
		verdict = "correct"
	}
	return fmt.Sprintf("~%.0f bits — %s · %s hors ligne", bits, verdict, crackTime(bits))
}

// crackTime donne l'ordre de grandeur, pas une prédiction : seule la puissance
// de dix compte, et l'hypothèse de débit peut se tromper d'un facteur cent.
func crackTime(bits float64) string {
	if bits <= 0 {
		return "instantané"
	}
	secondes := math.Pow(2, bits) / offlineGuessRate
	switch {
	case secondes < 60:
		return "cassé en quelques secondes"
	case secondes < 3600:
		return "cassé en quelques minutes"
	case secondes < 86400:
		return "cassé en quelques heures"
	case secondes < 30*86400:
		return "cassé en quelques jours"
	case secondes < 365*86400:
		return "cassé en quelques mois"
	case secondes < 1000*365*86400:
		return fmt.Sprintf("~%.0f ans", secondes/(365*86400))
	default:
		return "des millénaires"
	}
}

// compressHint adapte l'aide du champ compression : sur un dossier elle est
// proposée active, autant dire pourquoi.
// verifySucces adapte la phrase de fin : sur une archive, ce qui est contrôlé
// est bien qu'elle serait extractible, pas seulement lisible.
func verifySucces(archive bool) string {
	if archive {
		return "archive intacte, extractible, rien écrit sur le disque"
	}
	return "fichier intact, déchiffrable, rien écrit sur le disque"
}

// compEncodee traduit la réponse de l'interface en identifiant de compression.
func compEncodee(compresser bool) byte {
	if compresser {
		return pkg.CompZstd
	}
	return pkg.CompNone
}

func compressHint(dossier bool) string {
	if dossier {
		return "proposée active sur un dossier · laisse fuiter la compressibilité du contenu"
	}
	return "réduit la taille, mais laisse fuiter la compressibilité du contenu"
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			// filepath.Join et non une concaténation : sous Windows, coller
			// « /docs » à « C:\Users\x » produisait un chemin aux séparateurs
			// mélangés. Go l'accepte, mais il s'affiche mal partout.
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// kdfHint décrit un profil KDF pour la TUI. La mémoire est annoncée parce
// qu'elle sera aussi exigée au déchiffrement.
func kdfHint(p pkg.KDFProfile) string {
	return fmt.Sprintf("%s · %d Mio de mémoire, exigés aussi au déchiffrement",
		p.KDFLabel(), p.MemoryMiB())
}

// metaEncodee traduit la réponse de la TUI en mode de métadonnées.
func metaEncodee(garder bool) pkg.MetadataMode {
	if garder {
		return pkg.MetadataMinimal
	}
	return pkg.MetadataNone
}

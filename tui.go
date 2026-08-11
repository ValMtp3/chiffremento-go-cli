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

// runTUI enchaîne le formulaire puis l'écran de progression.
func runTUI() error {
	action := "enc"
	path := ""
	mode := "saisie"

	if err := mainForm(&action, &path, &mode).Run(); err != nil {
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

// mainForm demande l'opération, puis la cible — au clavier ou en naviguant.
//
// Les deux groupes de désignation sont exclusifs : `WithHideFunc` en masque un
// selon le choix précédent. Le champ texte reste le chemin rapide, parce qu'un
// glisser-déposer ou un chemin collé n'a rien à gagner d'un explorateur ; celui
// -ci sert quand on ne sait plus où est le fichier.
//
// Extrait de runTUI pour être pilotable depuis les tests.
func mainForm(action *string, path *string, mode *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Key("action").
				Title("opération").
				Options(
					huh.NewOption("chiffrer un fichier ou un dossier", "enc"),
					huh.NewOption("déchiffrer un fichier", "dec"),
					huh.NewOption("vérifier un fichier (sans rien écrire)", "verify"),
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

		huh.NewGroup(
			huh.NewInput().
				Key("path").
				Title("fichier ou dossier").
				Placeholder("chemin du fichier ou glisser deposer le fichier/dossier").
				Value(path).
				Validate(func(s string) error { return validateTarget(s, *action) }),
		).WithHideFunc(func() bool { return *mode != "saisie" }),

		huh.NewGroup(
			filePickerField(action, path),
		).WithHideFunc(func() bool { return *mode != "parcourir" }),
	).WithTheme(formTheme()).WithShowHelp(true)
}

// filePickerField construit l'explorateur. Il vient de huh, donc de bubbles :
// aucune dépendance nouvelle.
//
// Les dossiers sont sélectionnables parce qu'ils sont une cible légitime au
// chiffrement. Le filtrage par type n'est volontairement pas utilisé : c'est
// `validateTarget` qui tranche, dans les deux chemins de saisie, avec ses
// messages en français — `AllowedTypes` afficherait les siens en anglais et
// ferait exister deux règles là où il n'en faut qu'une.
//
// La description rappelle la navigation, qui n'est pas devinable : la flèche
// droite entre dans un dossier, entrée choisit ce qui est sous le curseur.
func filePickerField(action *string, path *string) huh.Field {
	return huh.NewFilePicker().
		Key("picker").
		Title("fichier ou dossier").
		Description("→ entrer dans un dossier · entrée choisir · ← revenir").
		CurrentDirectory(".").
		DirAllowed(true).
		FileAllowed(true).
		ShowSize(true).
		Height(12).
		Value(path).
		Validate(func(s string) error { return validateTarget(s, *action) })
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
		return errors.New("fichier introuvable")
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
	comp := pkg.CompNone
	if estDossier {
		comp = pkg.CompZstd
	}
	pad := false
	password, confirm := "", ""

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[byte]().
				Title("algorithme").
				Description(pkg.DefaultKDFLabel()).
				Options(
					huh.NewOption("aes-256-gcm  (défaut)", pkg.AlgoAES),
					huh.NewOption("chacha20-poly1305", pkg.AlgoChaCha),
					huh.NewOption("cascade  chacha20 + aes  (parano)", pkg.AlgoCascade),
				).
				Value(&algo),

			huh.NewSelect[byte]().
				Title("compresser avant chiffrement").
				Description(compressHint(estDossier)).
				Options(
					huh.NewOption("aucune", pkg.CompNone),
					huh.NewOption("zstd  (rapide, recommandé)", pkg.CompZstd),
					huh.NewOption("gzip  (relisible par les versions 2.x)", pkg.CompGzip),
				).
				Value(&comp),

			huh.NewConfirm().
				Title("masquer la taille réelle").
				DescriptionFunc(func() string { return padHint(comp) }, &comp).
				Affirmative("oui").
				Negative("non").
				Value(&pad).
				Validate(func(v bool) error {
					if v && comp != pkg.CompNone {
						return errors.New("incompatible avec la compression : la taille d'un fichier compressé dépend du contenu")
					}
					return nil
				}),
		),
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
			Algo: algo, Comp: comp, Pad: pad, Progress: p,
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
	if d.Version == 1 {
		details += "\nfichier produit par une version 1.x : lecture seule, il sera relu tel quel"
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
		Success: "fichier intact, déchiffrable, rien écrit sur le disque",
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
func compressHint(dossier bool) string {
	if dossier {
		return "zstd par défaut sur un dossier · laisse fuiter la compressibilité du contenu"
	}
	return "réduit la taille, mais laisse fuiter la compressibilité du contenu"
}

// padHint explique le remplissage, et pourquoi il est indisponible dès qu'une
// compression est choisie.
func padHint(comp byte) string {
	if comp != pkg.CompNone {
		return "indisponible avec la compression : la taille dépendrait alors du contenu"
	}
	return "arrondit la taille au palier supérieur (jusqu'à ~12 % de disque en plus)"
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

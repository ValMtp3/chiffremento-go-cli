package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
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

	if err := mainForm(&action, &path).Run(); err != nil {
		return err
	}
	path = strings.TrimSpace(expandHome(path))

	if action == "dec" {
		return tuiDecrypt(path)
	}
	return tuiEncrypt(path)
}

// mainForm demande l'opération et le fichier. Extrait de runTUI pour être
// pilotable depuis les tests.
func mainForm(action *string, path *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Key("action").
				Title("opération").
				Options(
					huh.NewOption("chiffrer un fichier", "enc"),
					huh.NewOption("déchiffrer un fichier", "dec"),
				).
				Value(action),

			huh.NewInput().
				Key("path").
				Title("fichier").
				Placeholder("chemin du fichier").
				Value(path).
				Validate(func(s string) error { return validateTarget(s, *action) }),
		),
	).WithTheme(formTheme()).WithShowHelp(true)
}

// validateTarget refuse tout de suite les cas qui échoueraient plus loin :
// fichier absent, répertoire, ou extension incohérente avec l'opération.
func validateTarget(s, action string) error {
	s = strings.TrimSpace(expandHome(s))
	if s == "" {
		return errors.New("indique un fichier")
	}
	info, err := os.Stat(s)
	if err != nil {
		return errors.New("fichier introuvable")
	}
	if info.IsDir() {
		return errors.New("c'est un répertoire")
	}
	if action == "dec" && !strings.HasSuffix(s, extension) {
		return errors.New("un fichier à déchiffrer doit porter l'extension " + extension)
	}
	if action == "enc" && strings.HasSuffix(s, extension) {
		return errors.New("ce fichier est déjà chiffré")
	}
	return nil
}

func tuiEncrypt(path string) error {
	algo := pkg.AlgoAES
	compress := false
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

			huh.NewConfirm().
				Title("compresser avant chiffrement").
				Description("réduit la taille, mais laisse fuiter la compressibilité du contenu").
				Affirmative("oui").
				Negative("non").
				Value(&compress),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("mot de passe").
				Description("jamais affiché, jamais visible dans ps ni dans l'historique").
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
	info := jobInfo{
		Action: "chiffrement",
		In:     path,
		Out:    out,
		AEAD:   pkg.AlgoName(algo),
		KDF:    pkg.DefaultKDFLabel(),
		Salt:   "16 o aléatoires · en-tête lié à la clé",
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Encrypt(path, out, []byte(password), pkg.Options{
			Algo: algo, Compress: compress, Progress: p,
		})
	})
}

func tuiDecrypt(path string) error {
	// L'en-tête est lisible sans mot de passe : on affiche les vrais
	// paramètres du fichier avant de demander quoi que ce soit.
	version, algo, kdf, compressed, err := pkg.Inspect(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", version, algo, kdf)
	if compressed {
		details += " · compressé"
	}
	if version == 1 {
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
		Action: "déchiffrement",
		In:     path,
		Out:    out,
		AEAD:   algo,
		KDF:    kdf,
		Salt:   fmt.Sprintf("format v%d · lu dans l'en-tête", version),
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Decrypt(path, out, []byte(password), pkg.Options{Progress: p})
	})
}

// runJob lance l'opération dans une goroutine et affiche l'écran animé.
func runJob(info jobInfo, op func(progress func(done, total int64)) error) error {
	if st, err := os.Stat(info.In); err == nil {
		info.Size = st.Size()
	}

	var done atomic.Int64
	model := newProgressModel(info, &done)
	prog := tea.NewProgram(model)

	var opErr error
	go func() {
		opErr = op(func(d, _ int64) { done.Store(d) })
		prog.Send(doneMsg{err: opErr})
	}()

	if _, err := prog.Run(); err != nil {
		return err
	}
	if opErr != nil {
		return opErr
	}

	fmt.Printf("  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(info.Out))
	return nil
}

// --- Saisie du mot de passe hors TUI ------------------------------------

// readPassword récupère le mot de passe sans jamais le faire transiter par la
// ligne de commande : le flag -key de la v1 était visible dans `ps aux` pour
// tous les utilisateurs de la machine et finissait dans l'historique du shell.
//
// Si l'entrée standard n'est pas un terminal, on lit une ligne sur stdin.
// C'est le seul chemin non interactif, et il ne fuite ni dans ps ni dans la
// liste des arguments : echo 'motdepasse' | chiffremento -mode enc -in f
func readPassword(confirm bool) ([]byte, error) {
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

func validatePassword(s string) error {
	if s == "" {
		return errors.New("le mot de passe ne peut pas être vide")
	}
	return nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

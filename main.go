package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"chiffremento-cli/pkg"
)

var version = "dev"

const extension = ".chto"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, styleError.Render("erreur :"), err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "afficher la version")
	mode := flag.String("mode", "", "enc (chiffrer), dec (déchiffrer) ou info (inspecter un .chto)")
	fileIn := flag.String("in", "", "fichier d'entrée")
	compress := flag.Bool("comp", false, "compresser les données avant chiffrement")
	chacha := flag.Bool("chacha", false, "utiliser ChaCha20-Poly1305 au lieu d'AES-GCM")
	parano := flag.Bool("parano", false, "mode parano : double chiffrement en cascade (chacha20 + aes), plus lent")
	flag.Usage = usage

	// Sans le moindre argument, dans un vrai terminal : interface guidée.
	// Dans un pipe ou en CI on garde l'usage classique, sinon la TUI bloquerait
	// sur une entrée qui n'arrivera jamais.
	if len(os.Args) == 1 {
		if isInteractive() {
			return runTUI()
		}
		usage()
		return errors.New("aucun argument fourni (l'interface guidée nécessite un terminal)")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("chiffremento %s\n", version)
		return nil
	}

	if *mode == "" || *fileIn == "" {
		usage()
		return errors.New("-mode et -in sont obligatoires")
	}

	if *mode != "enc" && (*compress || *chacha || *parano) {
		fmt.Fprintln(os.Stderr, styleDim.Render(
			"note : -comp, -chacha et -parano n'ont d'effet qu'en mode enc, ils sont ignorés ici"))
	}

	switch *mode {
	case "enc":
		algo, err := chooseAlgo(*chacha, *parano)
		if err != nil {
			return err
		}
		return doEncrypt(*fileIn, algo, *compress)
	case "dec":
		return doDecrypt(*fileIn)
	case "info":
		return doInfo(*fileIn)
	default:
		return fmt.Errorf("mode inconnu %q (attendu enc, dec ou info)", *mode)
	}
}

// chooseAlgo refuse les combinaisons contradictoires. La v1 laissait -parano
// écraser -chacha en silence.
func chooseAlgo(chacha, parano bool) (byte, error) {
	switch {
	case chacha && parano:
		return 0, errors.New("-chacha et -parano s'excluent : le mode parano utilise déjà chacha20 en couche externe")
	case parano:
		return pkg.AlgoCascade, nil
	case chacha:
		return pkg.AlgoChaCha, nil
	default:
		return pkg.AlgoAES, nil
	}
}

func doEncrypt(in string, algo byte, compress bool) error {
	if strings.HasSuffix(in, extension) {
		return fmt.Errorf("%s porte déjà l'extension %s : il semble déjà chiffré", in, extension)
	}
	out := in + extension
	if err := checkPaths(in, out); err != nil {
		return err
	}

	password, err := readPassword(true)
	if err != nil {
		return err
	}
	defer zero(password)

	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("chiffrement  "), pkg.AlgoName(algo))
	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("kdf          "), pkg.DefaultKDFLabel())

	if err := pkg.Encrypt(in, out, password, pkg.Options{Algo: algo, Compress: compress}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", styleAccent.Render("✓"), out)
	return nil
}

func doDecrypt(in string) error {
	if !strings.HasSuffix(in, extension) {
		return fmt.Errorf("un fichier à déchiffrer doit porter l'extension %s", extension)
	}
	out := strings.TrimSuffix(in, extension)
	if filepath.Base(out) == "" || filepath.Base(in) == extension {
		return fmt.Errorf("%s ne donne aucun nom de sortie exploitable", in)
	}
	if err := checkPaths(in, out); err != nil {
		return err
	}

	// L'en-tête est lisible sans mot de passe : autant annoncer les vrais
	// paramètres du fichier avant de demander quoi que ce soit.
	version, algo, kdf, compressed, err := pkg.Inspect(in)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s format v%d · %s · %s%s\n", styleDim.Render("fichier      "),
		version, algo, kdf, compressedSuffix(compressed))

	password, err := readPassword(false)
	if err != nil {
		return err
	}
	defer zero(password)

	if err := pkg.Decrypt(in, out, password, pkg.Options{}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", styleAccent.Render("✓"), out)
	return nil
}

// doInfo affiche l'en-tête d'un .chto sans le déchiffrer : ni mot de passe, ni
// écriture sur le disque.
func doInfo(in string) error {
	version, algo, kdf, compressed, err := pkg.Inspect(in)
	if err != nil {
		return err
	}
	st, err := os.Stat(in)
	if err != nil {
		return err
	}

	line := func(label, value string) {
		fmt.Printf("%s%s\n", styleLabel.Render(label), styleText.Render(value))
	}
	line("fichier", in)
	line("taille", fmt.Sprintf("%d octets", st.Size()))
	line("format", fmt.Sprintf("v%d", version))
	line("aead", algo)
	line("kdf", kdf)
	line("gzip", map[bool]string{true: "oui", false: "non"}[compressed])
	if version == 1 {
		fmt.Println(styleDim.Render("  produit par une version 1.x : lecture seule, les nouveaux fichiers sont en v2"))
	}
	return nil
}

func compressedSuffix(c bool) string {
	if c {
		return " · compressé"
	}
	return ""
}

// checkPaths attrape les cas où l'on écraserait la source par la sortie.
func checkPaths(in, out string) error {
	if in == out {
		return errors.New("le fichier d'entrée et le fichier de sortie sont identiques")
	}
	absIn, err1 := filepath.Abs(in)
	absOut, err2 := filepath.Abs(out)
	if err1 == nil && err2 == nil && absIn == absOut {
		return errors.New("le fichier d'entrée et le fichier de sortie sont identiques")
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `chiffremento %s — chiffrement de fichiers

  chiffremento                      interface guidée
  chiffremento -mode enc -in FICHIER [options]
  chiffremento -mode dec -in FICHIER%s
  chiffremento -mode info -in FICHIER%s

Le mot de passe n'est jamais passé en argument : il est demandé de façon
masquée, ou lu sur l'entrée standard si celle-ci n'est pas un terminal.

Options :
`, version, extension, extension)
	flag.PrintDefaults()
}

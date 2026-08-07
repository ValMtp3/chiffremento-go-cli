package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"chiffremento-cli/pkg"
)

var version = "dev"

const extension = ".chto"

func main() {
	installSignalHandler()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, styleError.Render("erreur :"), err)
		os.Exit(1)
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "afficher la version")
	mode := flag.String("mode", "", "enc (chiffrer), dec (déchiffrer), verify (contrôler) ou info (inspecter)")
	fileIn := flag.String("in", "", "fichier d'entrée")
	compress := flag.Bool("comp", false, "compresser les données avant chiffrement")
	kdfProfile := flag.String("kdf", string(pkg.KDFStandard), "profil Argon2: standard, fort ou parano (enc)")
	metadataMode := flag.String("meta", string(pkg.MetadataNone), "metadata: none (défaut) ou minimal (enc)")
	chacha := flag.Bool("chacha", false, "utiliser ChaCha20-Poly1305 au lieu d'AES-GCM")
	parano := flag.Bool("parano", false, "mode parano : double chiffrement en cascade (chacha20 + aes), plus lent")
	parano2 := flag.Bool("parano2", false, "double chiffrement inverse (aes + chacha), plus lent")
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

	if *mode == "" {
		usage()
		return errors.New("-mode est obligatoire")
	}
	if *mode != "bench" && *fileIn == "" {
		usage()
		return errors.New("-in est obligatoire pour ce mode")
	}

	if *mode != "enc" && (*compress || *chacha || *parano || *parano2 || *kdfProfile != string(pkg.KDFStandard) || *metadataMode != string(pkg.MetadataNone)) {
		fmt.Fprintln(os.Stderr, styleDim.Render(
			"note : -comp, -kdf, -meta, -chacha, -parano et -parano2 n'ont d'effet qu'en mode enc, ils sont ignorés ici"))
	}

	switch *mode {
	case "enc":
		algo, err := chooseAlgo(*chacha, *parano, *parano2)
		if err != nil {
			return err
		}
		profile, err := pkg.ParseKDFProfile(*kdfProfile)
		if err != nil {
			return err
		}
		meta, err := pkg.ParseMetadataMode(*metadataMode)
		if err != nil {
			return err
		}
		return doEncrypt(*fileIn, algo, *compress, profile, meta)
	case "dec":
		return doDecrypt(*fileIn)
	case "verify":
		return doVerify(*fileIn)
	case "info":
		return doInfo(*fileIn)
	case "bench":
		return doBenchmark()
	default:
		return fmt.Errorf("mode inconnu %q (attendu enc, dec, verify, info ou bench)", *mode)
	}
}

// installSignalHandler évite qu'un Ctrl+C laisse un .chto-tmp-* orphelin :
// les defer ne s'exécutent pas quand le processus est interrompu.
func installSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		pkg.CleanupTemporaries()
		fmt.Fprintln(os.Stderr, "\ninterrompu")
		os.Exit(130)
	}()
}

// chooseAlgo refuse les combinaisons contradictoires. La v1 laissait -parano
// écraser -chacha en silence.
func chooseAlgo(chacha, parano, parano2 bool) (byte, error) {
	switch {
	case (btoi(chacha) + btoi(parano) + btoi(parano2)) > 1:
		return 0, errors.New("-chacha, -parano et -parano2 s'excluent")
	case parano:
		return pkg.AlgoCascade, nil
	case parano2:
		return pkg.AlgoCascadeReverse, nil
	case chacha:
		return pkg.AlgoChaCha, nil
	default:
		return pkg.AlgoAES, nil
	}
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func doEncrypt(in string, algo byte, compress bool, profile pkg.KDFProfile, metadata pkg.MetadataMode) error {
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
	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("kdf          "), pkg.KDFLabelForProfile(profile))
	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("metadata     "), metadata)

	if err := pkg.Encrypt(in, out, password, pkg.Options{
		Algo: algo, Compress: compress, KDFProfile: profile, Metadata: metadata,
	}); err != nil {
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
	version, algo, kdf, metadata, compressed, err := pkg.Inspect(in)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s format v%d · %s · %s%s\n", styleDim.Render("fichier      "),
		version, algo, kdf, compressedSuffix(compressed))
	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("metadata     "), metadata)

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

// doVerify contrôle qu'un fichier est intact et déchiffrable sans rien écrire
// sur le disque. Pratique pour vérifier une sauvegarde sans l'extraire.
func doVerify(in string) error {
	if !strings.HasSuffix(in, extension) {
		return fmt.Errorf("un fichier à vérifier doit porter l'extension %s", extension)
	}

	version, algo, kdf, metadata, compressed, err := pkg.Inspect(in)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s format v%d · %s · %s%s\n", styleDim.Render("fichier      "),
		version, algo, kdf, compressedSuffix(compressed))
	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("metadata     "), metadata)

	password, err := readPassword(false)
	if err != nil {
		return err
	}
	defer zero(password)

	if err := pkg.Verify(in, password, pkg.Options{}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", styleAccent.Render("✓"),
		styleText.Render("fichier intact, déchiffrable, rien écrit sur le disque"))
	return nil
}

// doInfo affiche l'en-tête d'un .chto sans le déchiffrer : ni mot de passe, ni
// écriture sur le disque.
func doInfo(in string) error {
	version, algo, kdf, metadata, compressed, err := pkg.Inspect(in)
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
	line("metadata", metadata)
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

  chiffremento                        interface guidée
  chiffremento -mode enc    -in FICHIER [options]
  chiffremento -mode dec    -in FICHIER%s
  chiffremento -mode verify -in FICHIER%s   contrôle sans rien écrire
  chiffremento -mode info   -in FICHIER%s   en-tête, sans mot de passe
  chiffremento -mode bench                 benchmark KDF local

Le mot de passe n'est jamais passé en argument : il est demandé de façon
masquée, ou lu sur l'entrée standard si celle-ci n'est pas un terminal.

Options :
`, version, extension, extension, extension)
	flag.PrintDefaults()
}

func doBenchmark() error {
fmt.Fprintln(os.Stderr, styleDim.Render("benchmark"), "argon2id (standard/fort/parano)")
report := pkg.BenchmarkKDF([]byte("chiffremento-benchmark"))
for _, r := range report.Results {
	if r.Err != nil {
		fmt.Fprintf(os.Stderr, "  - %-8s %s -> erreur: %v\n", r.Profile, r.KDFLabel, r.Err)
		continue
	}
	fmt.Fprintf(os.Stderr, "  - %-8s %s -> %s\n", r.Profile, r.KDFLabel, r.Duration.Round(10*time.Millisecond))
}
fmt.Fprintf(os.Stderr, "%s recommande -kdf %s\n", styleAccent.Render("✓"), report.Recommended)
return nil
}

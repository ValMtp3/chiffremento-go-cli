package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
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
	mode := flag.String("mode", "", "enc (chiffrer), dec (déchiffrer), verify (contrôler), info (inspecter) ou bench (mesurer)")
	fileIn := flag.String("in", "", "fichier ou dossier d'entrée, ou - pour l'entrée standard (dossier en mode enc uniquement)")
	fileOut := flag.String("out", "", "destination (défaut : entrée + "+extension+" en enc, entrée sans l'extension en dec) ; - pour la sortie standard")
	compress := flag.Bool("comp", false, "compresser les données en zstd avant chiffrement")
	pad := flag.Bool("pad", false, "masquer la taille réelle en ajoutant du remplissage ; s'exclut avec -comp")
	chacha := flag.Bool("chacha", false, "utiliser ChaCha20-Poly1305 au lieu d'AES-GCM")
	parano := flag.Bool("parano", false, "mode parano : double chiffrement en cascade (chacha20 + aes), plus lent")
	kdf := flag.String("kdf", "", "coût de la dérivation de clé : standard (défaut), fort ou maximum")
	meta := flag.String("meta", "", "métadonnées conservées dans le chiffré : none (défaut) ou minimal (nom et date)")
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

	// bench ne prend pas d'entrée : il ne lit ni n'écrit aucun fichier.
	if *mode == "bench" {
		return doBench()
	}

	if *mode == "" || *fileIn == "" {
		usage()
		return errors.New("-mode et -in sont obligatoires")
	}

	if *mode != "enc" && (*compress || *chacha || *parano || *pad || *kdf != "" || *meta != "") {
		fmt.Fprintln(os.Stderr, styleDim.Render(
			"note : -comp, -pad, -chacha, -parano, -kdf et -meta n'ont d'effet qu'en mode enc, ils sont ignorés ici"))
	}
	if *mode == "info" && *fileOut != "" {
		fmt.Fprintln(os.Stderr, styleDim.Render("note : -out n'a pas d'effet en mode info, il est ignoré"))
	}

	switch *mode {
	case "enc":
		algo, err := chooseAlgo(*chacha, *parano)
		if err != nil {
			return err
		}
		profile, err := pkg.ParseKDFProfile(*kdf)
		if err != nil {
			return err
		}
		metaMode, err := pkg.ParseMetadataMode(*meta)
		if err != nil {
			return err
		}
		return doEncrypt(*fileIn, *fileOut, pkg.Options{
			Algo: algo, Comp: chooseComp(*compress), Pad: *pad,
			KDF: profile, Metadata: metaMode,
		})
	case "dec":
		return doDecrypt(*fileIn, *fileOut)
	case "verify":
		return doVerify(*fileIn)
	case "info":
		return doInfo(*fileIn)
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

// chooseComp traduit -comp en identifiant de compression.
//
// Il n'y a plus de choix d'algorithme : zstd remplace gzip partout, environ huit
// fois plus rapide à taille comparable. gzip reste lu pour les anciens fichiers,
// jamais écrit — un drapeau pour le produire n'aurait servi qu'à fabriquer des
// fichiers plus lents.
func chooseComp(compress bool) byte {
	if compress {
		return pkg.CompZstd
	}
	return pkg.CompNone
}

// isStream reconnaît le tiret conventionnel des flux standard.
func isStream(p string) bool { return p == "-" }

func doEncrypt(in, out string, opts pkg.Options) error {
	algo, comp, pad, kdf, meta := opts.Algo, opts.Comp, opts.Pad, opts.KDF, opts.Metadata
	if algo == 0 {
		algo = pkg.AlgoAES
	}
	if kdf == "" {
		kdf = pkg.KDFStandard
	}

	// Un dossier glissé dans le terminal ou complété par le shell arrive
	// souvent avec un séparateur final : sans ce nettoyage, la sortie
	// s'appellerait « photos/.chto ».
	if !isStream(in) {
		in = trimTrailingSeparator(in)
		if strings.HasSuffix(in, extension) {
			return fmt.Errorf("%s porte déjà l'extension %s : il semble déjà chiffré", in, extension)
		}
	}
	if out == "" {
		if isStream(in) {
			return errors.New("-out est obligatoire quand l'entrée est l'entrée standard")
		}
		out = in + extension
	}
	if !isStream(in) && !isStream(out) {
		if err := checkPaths(in, out); err != nil {
			return err
		}
	}

	password, err := readPassword(true, isStream(in))
	if err != nil {
		return err
	}
	defer zero(password)

	fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("chiffrement  "), pkg.AlgoName(algo))
	fmt.Fprintf(os.Stderr, "%s %s (%s)\n", styleDim.Render("kdf          "), kdf.KDFLabel(), kdf)
	if comp != pkg.CompNone {
		fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("compression  "), pkg.CompName(comp))
	}
	if pad {
		fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("remplissage  "), "taille arrondie au palier supérieur")
	}
	if meta == pkg.MetadataMinimal {
		fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("métadonnées  "),
			"nom d'origine et date conservés dans le chiffré")
	}
	if !isStream(in) {
		if st, err := os.Stat(in); err == nil && st.IsDir() {
			fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("contenu      "),
				"dossier, empaqueté en tar au fil du chiffrement")
		}
	}

	if err := encryptTo(in, out, password, opts); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", styleAccent.Render("✓"), describeDest(out))
	return nil
}

// encryptTo aiguille entre l'écriture atomique sur disque et les flux standard.
// Le chemin « fichier vers fichier » reste celui de pkg.Encrypt, qui seul offre
// l'écriture atomique.
func encryptTo(in, out string, password []byte, opts pkg.Options) error {
	if !isStream(in) && !isStream(out) {
		return pkg.Encrypt(in, out, password, opts)
	}

	src, size, closeSrc, err := openSource(in)
	if err != nil {
		return err
	}
	defer closeSrc()

	dst, closeDst, err := openDest(out)
	if err != nil {
		return err
	}
	defer closeDst()

	if err := pkg.EncryptStream(dst, src, size, password, opts); err != nil {
		return err
	}
	return closeDst()
}

func doDecrypt(in, out string) error {
	if !isStream(in) && !strings.HasSuffix(in, extension) {
		return fmt.Errorf("un fichier à déchiffrer doit porter l'extension %s", extension)
	}
	if out == "" {
		if isStream(in) {
			return errors.New("-out est obligatoire quand l'entrée est l'entrée standard")
		}
		out = strings.TrimSuffix(in, extension)
		if filepath.Base(out) == "" || filepath.Base(in) == extension {
			return fmt.Errorf("%s ne donne aucun nom de sortie exploitable", in)
		}
	}
	if !isStream(in) && !isStream(out) {
		if err := checkPaths(in, out); err != nil {
			return err
		}
	}

	// L'en-tête est lisible sans mot de passe : autant annoncer les vrais
	// paramètres du fichier avant de demander quoi que ce soit. Sur un flux,
	// c'est impossible sans consommer les octets, donc on s'en passe.
	if !isStream(in) {
		d, err := pkg.Inspect(in)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s format v%d · %s · %s%s\n", styleDim.Render("fichier      "),
			d.Version, d.Algo, d.KDF, detailsSuffix(d))
		if d.Archive {
			if isStream(out) {
				fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("sortie       "),
					"flux tar sur la sortie standard (à passer à tar)")
			} else {
				fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("sortie       "),
					out+string(os.PathSeparator)+" (dossier, doit ne pas exister)")
			}
		}
	}

	password, err := readPassword(false, isStream(in))
	if err != nil {
		return err
	}
	defer zero(password)

	meta, err := decryptTo(in, out, password)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", styleAccent.Render("✓"), describeDest(out))

	// Le nom d'origine n'est lisible qu'après authentification : impossible de
	// l'annoncer plus tôt, et impossible de nommer la sortie avec avant d'avoir
	// vérifié le fichier. On le signale donc, sans renommer d'autorité.
	if meta != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("nom d'origine"), meta.Name)
		if !isStream(out) && filepath.Base(out) != meta.Name {
			fmt.Fprintf(os.Stderr, "%s %s\n", styleDim.Render("             "),
				"diffère du nom de sortie ; à renommer si besoin")
		}
	}
	return nil
}

// decryptTo aiguille comme encryptTo. Sur la sortie standard, une archive sort
// telle quelle, en tar : il n'y a rien à extraire dans un tube.
func decryptTo(in, out string, password []byte) (*pkg.FileMetadata, error) {
	if !isStream(in) && !isStream(out) {
		res, err := pkg.DecryptTo(in, out, password, pkg.Options{})
		return res.Metadata, err
	}

	src, _, closeSrc, err := openSource(in)
	if err != nil {
		return nil, err
	}
	defer closeSrc()

	dst, closeDst, err := openDest(out)
	if err != nil {
		return nil, err
	}
	defer closeDst()

	// Sur un flux, les métadonnées ne sont pas remontées : il n'y a pas de
	// fichier de sortie à qui appliquer une date, et l'appelant a déjà choisi
	// où vont les octets.
	if err := pkg.DecryptStream(dst, src, password, pkg.Options{}); err != nil {
		return nil, err
	}
	return nil, closeDst()
}

// doVerify contrôle qu'un fichier est intact et déchiffrable sans rien écrire
// sur le disque. Pratique pour vérifier une sauvegarde sans l'extraire.
func doVerify(in string) error {
	if !isStream(in) && !strings.HasSuffix(in, extension) {
		return fmt.Errorf("un fichier à vérifier doit porter l'extension %s", extension)
	}

	// Sur un flux, l'en-tête n'est pas relisible d'avance : on ne peut donc pas
	// savoir s'il s'agit d'une archive avant de l'avoir déchiffrée.
	archive := false
	if !isStream(in) {
		d, err := pkg.Inspect(in)
		if err != nil {
			return err
		}
		archive = d.Archive
		fmt.Fprintf(os.Stderr, "%s format v%d · %s · %s%s\n", styleDim.Render("fichier      "),
			d.Version, d.Algo, d.KDF, detailsSuffix(d))
	}

	password, err := readPassword(false, isStream(in))
	if err != nil {
		return err
	}
	defer zero(password)

	if isStream(in) {
		if err := pkg.VerifyStream(os.Stdin, password, pkg.Options{}); err != nil {
			return err
		}
	} else if err := pkg.Verify(in, password, pkg.Options{}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", styleAccent.Render("✓"),
		styleText.Render(verifySucces(archive)))
	return nil
}

// doInfo affiche l'en-tête d'un .chto sans le déchiffrer : ni mot de passe, ni
// écriture sur le disque.
func doInfo(in string) error {
	if isStream(in) {
		return errors.New("info a besoin d'un fichier : l'en-tête d'un flux ne peut pas être relu sans le consommer")
	}
	d, err := pkg.Inspect(in)
	if err != nil {
		return err
	}
	st, err := os.Stat(in)
	if err != nil {
		return err
	}

	line := func(label, value string) {
		fmt.Printf("%s%s\n", styleInfoLabel.Render(label), styleText.Render(value))
	}
	line("fichier", in)
	line("taille", fmt.Sprintf("%d octets", st.Size()))
	line("format", fmt.Sprintf("v%d", d.Version))
	line("aead", d.Algo)
	line("kdf", d.KDF)
	line("compression", d.Comp)
	line("contenu", map[bool]string{true: "dossier (archive tar)", false: "fichier"}[d.Archive])
	line("remplissage", map[bool]string{true: "oui, taille réelle masquée", false: "non"}[d.Padded])
	line("métadonnées", map[bool]string{
		true:  "oui, nom et date à l'intérieur du chiffré",
		false: "non",
	}[d.Metadata])
	if d.Version < 3 {
		fmt.Println(styleDim.Render(fmt.Sprintf(
			"  produit par un format v%d : lecture seule, les nouveaux fichiers sont en v3", d.Version)))
	}
	return nil
}

// openSource ouvre l'entrée et renvoie sa taille, ou -1 si elle est inconnue.
func openSource(in string) (io.Reader, int64, func(), error) {
	if isStream(in) {
		return os.Stdin, -1, func() {}, nil
	}
	f, err := os.Open(in)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("lecture: %w", err)
	}
	size := int64(-1)
	if st, err := f.Stat(); err == nil && st.Mode().IsRegular() {
		size = st.Size()
	}
	return f, size, func() { f.Close() }, nil
}

// openDest ouvre la destination. La fonction de fermeture renvoyée est
// idempotente : on l'appelle explicitement pour remonter l'erreur de fermeture,
// et en defer pour ne rien laisser ouvert en cas d'échec.
func openDest(out string) (io.Writer, func() error, error) {
	if isStream(out) {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(out)
	if err != nil {
		return nil, nil, fmt.Errorf("création de %s: %w", out, err)
	}
	closed := false
	return f, func() error {
		if closed {
			return nil
		}
		closed = true
		return f.Close()
	}, nil
}

func describeDest(out string) string {
	if isStream(out) {
		return "écrit sur la sortie standard"
	}
	return out
}

func detailsSuffix(d pkg.Details) string {
	s := ""
	if d.Compressed {
		s += " · " + d.Comp
	}
	if d.Archive {
		s += " · dossier"
	}
	if d.Padded {
		s += " · taille masquée"
	}
	return s
}

// trimTrailingSeparator retire les séparateurs finaux sans jamais réduire un
// chemin à la chaîne vide : "photos/" devient "photos", mais "/" reste "/".
func trimTrailingSeparator(p string) string {
	for len(p) > 1 && os.IsPathSeparator(p[len(p)-1]) {
		p = p[:len(p)-1]
	}
	return p
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
	fmt.Fprintf(os.Stderr, `chiffremento %s — chiffrement de fichiers et de dossiers

  chiffremento                        interface guidée
  chiffremento -mode enc    -in FICHIER|DOSSIER [-out CHEMIN] [options]
  chiffremento -mode dec    -in FICHIER%s      [-out CHEMIN]
  chiffremento -mode verify -in FICHIER%s      contrôle sans rien écrire
  chiffremento -mode info   -in FICHIER%s      en-tête, sans mot de passe

Un dossier est empaqueté en tar au fil du chiffrement, et recréé à l'identique
au déchiffrement.

-in - lit l'entrée standard, -out - écrit sur la sortie standard : l'outil est
donc composable. Sur un flux, l'écriture atomique n'existe pas et le clair sort
avant que la fin du fichier soit authentifiée — à réserver aux tubes.

  chiffremento -mode dec -in sauvegarde%s -out - | tar tf -

Le mot de passe n'est jamais passé en argument : il est demandé de façon
masquée, ou lu sur l'entrée standard si celle-ci n'est pas un terminal.

Options :
`, version, extension, extension, extension, extension)
	flag.PrintDefaults()
}

// doBench mesure les coûts sur cette machine. Ni lecture ni écriture de
// fichier, ni mot de passe : c'est de l'information, pas une opération.
func doBench() error {
	rep := pkg.Benchmark()

	fmt.Printf("%s%s\n\n", styleLabel.Render("machine"),
		styleText.Render(fmt.Sprintf("%d cœurs logiques", rep.CPUs)))

	fmt.Println(styleDim.Render("  dérivation de clé (argon2id)"))
	for _, m := range rep.KDF {
		marque := "  "
		if m.Profile == rep.Advised {
			marque = styleAccent.Render("→ ")
		}
		fmt.Printf("  %s%-10s %-24s %6d Mio  %8s\n", marque, m.Profile, m.Label,
			m.MemoryMiB, m.Duration.Round(time.Millisecond))
	}
	fmt.Printf("\n  %s\n", styleAccent.Render(rep.Advisory))
	fmt.Println(styleDim.Render("  la mémoire annoncée sera aussi exigée au déchiffrement"))

	fmt.Printf("\n%s\n", styleDim.Render("  débit de chiffrement"))
	for _, m := range rep.AEAD {
		if m.Err != nil {
			fmt.Printf("    %-34s %s\n", m.Name, styleDim.Render("mesure impossible : "+m.Err.Error()))
			continue
		}
		fmt.Printf("    %-34s %10s/s\n", m.Name, humanSize(m.BytesPerSec))
	}
	fmt.Printf("\n  %s\n", styleDim.Render(
		"sans accélération AES matérielle, chacha20 passe devant : c'est là que -chacha se justifie"))
	return nil
}

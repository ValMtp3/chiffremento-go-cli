package pkg

import (
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/sio"
)

// Options regroupe les réglages d'une opération. Elle remplace la série de
// booléens positionnels de la v1, où -chacha et -parano pouvaient se
// contredire sans que personne ne le signale.
type Options struct {
	// Algo vaut AlgoAES, AlgoChaCha ou AlgoCascade. Zéro équivaut à AlgoAES.
	// Ignoré au déchiffrement : l'algorithme est lu dans l'en-tête du fichier.
	Algo byte

	// Compress active gzip avant chiffrement. Ignoré au déchiffrement.
	Compress bool

	// Progress, si non nil, est appelé au fil de la copie avec le nombre
	// d'octets d'entrée déjà traités et la taille totale de l'entrée.
	Progress func(done, total int64)
}

// --- Écriture atomique -------------------------------------------------

// atomicFile écrit dans un temporaire du même répertoire et ne bascule sur la
// destination qu'une fois l'opération entièrement réussie.
//
// C'est ce qui empêche le scénario le plus destructeur de la v1 : os.Create
// tronquait la cible avant la moindre vérification, donc déchiffrer un .chto
// corrompu vers `doc.pdf` détruisait `doc.pdf`. Ça évite aussi de laisser sur
// le disque du clair non authentifié quand un fichier s'avère falsifié en
// cours de route.
type atomicFile struct {
	f         *os.File
	dest      string
	committed bool
}

func newAtomicFile(dest string) (*atomicFile, error) {
	dir := filepath.Dir(dest)
	f, err := os.CreateTemp(dir, ".chto-tmp-*")
	if err != nil {
		return nil, fmt.Errorf("création du fichier temporaire: %w", err)
	}
	// CreateTemp crée déjà en 0600 ; on le verrouille explicitement pour ne pas
	// dépendre de l'umask, et parce que la sortie déchiffrée est un secret.
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("permissions du fichier temporaire: %w", err)
	}
	return &atomicFile{f: f, dest: dest}, nil
}

// commit force l'écriture sur disque puis renomme. Après un commit réussi, la
// destination contient un fichier complet ou n'a pas été touchée du tout.
func (a *atomicFile) commit() error {
	if err := a.f.Sync(); err != nil {
		return fmt.Errorf("synchronisation sur disque: %w", err)
	}
	if err := a.f.Close(); err != nil {
		return fmt.Errorf("fermeture du fichier temporaire: %w", err)
	}
	if err := os.Rename(a.f.Name(), a.dest); err != nil {
		return fmt.Errorf("renommage vers %s: %w", a.dest, err)
	}
	a.committed = true
	return nil
}

// cleanup s'appelle en defer : sans commit, le temporaire disparaît.
func (a *atomicFile) cleanup() {
	if a.committed {
		return
	}
	a.f.Close()
	os.Remove(a.f.Name())
}

// writerOnly masque l'interface io.Closer du writer sous-jacent.
//
// sio.EncryptWriter.Close() ferme le writer qu'on lui a donné. Sans ce
// masquage, notre fichier temporaire serait fermé avant qu'on puisse le
// Sync() puis le renommer, et en mode cascade il serait même fermé deux fois.
type writerOnly struct{ io.Writer }

// progressReader compte les octets réellement lus. La progression affichée
// suit donc le travail effectif, jamais une estimation.
type progressReader struct {
	r     io.Reader
	done  int64
	total int64
	fn    func(done, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.done += int64(n)
		p.fn(p.done, p.total)
	}
	return n, err
}

// --- Flux de chiffrement -----------------------------------------------

// cascadeWriteCloser ferme les deux couches du mode cascade dans l'ordre et
// remonte la première erreur rencontrée. Les deux Close() sont toujours
// tentés, même si le premier échoue.
type cascadeWriteCloser struct {
	inner io.WriteCloser
	outer io.WriteCloser
}

func (c *cascadeWriteCloser) Write(p []byte) (int, error) { return c.inner.Write(p) }

func (c *cascadeWriteCloser) Close() error {
	errInner := c.inner.Close()
	errOuter := c.outer.Close()
	if errInner != nil {
		return errInner
	}
	return errOuter
}

func initCipherWriter(dst io.Writer, algo byte, keys *keySet) (io.WriteCloser, error) {
	switch algo {
	case AlgoCascade:
		outerWriter, err := sio.EncryptWriter(dst, sio.Config{
			Key:          keys.Outer,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		})
		if err != nil {
			return nil, fmt.Errorf("création du flux externe: %w", err)
		}
		innerWriter, err := sio.EncryptWriter(writerOnly{outerWriter}, sio.Config{
			Key:          keys.Inner,
			CipherSuites: []byte{sio.AES_256_GCM},
		})
		if err != nil {
			outerWriter.Close()
			return nil, fmt.Errorf("création du flux interne: %w", err)
		}
		return &cascadeWriteCloser{inner: innerWriter, outer: outerWriter}, nil

	case AlgoChaCha:
		return sio.EncryptWriter(dst, sio.Config{
			Key:          keys.Key,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		})

	case AlgoAES:
		return sio.EncryptWriter(dst, sio.Config{
			Key:          keys.Key,
			CipherSuites: []byte{sio.AES_256_GCM},
		})

	default:
		return nil, fmt.Errorf("algorithme inconnu : %d", algo)
	}
}

func initCipherReader(src io.Reader, algo byte, keys *keySet) (io.Reader, error) {
	switch algo {
	case AlgoCascade:
		outerReader, err := sio.DecryptReader(src, sio.Config{
			Key:          keys.Outer,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		})
		if err != nil {
			return nil, fmt.Errorf("init du déchiffrement externe: %w", err)
		}
		return sio.DecryptReader(outerReader, sio.Config{
			Key:          keys.Inner,
			CipherSuites: []byte{sio.AES_256_GCM},
		})

	case AlgoChaCha:
		return sio.DecryptReader(src, sio.Config{
			Key:          keys.Key,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		})

	case AlgoAES:
		return sio.DecryptReader(src, sio.Config{
			Key:          keys.Key,
			CipherSuites: []byte{sio.AES_256_GCM},
		})

	default:
		return nil, fmt.Errorf("algorithme inconnu : %d", algo)
	}
}

// --- API publique ------------------------------------------------------

// Encrypt chiffre inputPath vers outputPath. Le fichier produit est toujours
// au format v2.
func Encrypt(inputPath, outputPath string, password []byte, opts Options) error {
	algo := opts.Algo
	if algo == 0 {
		algo = AlgoAES
	}
	if err := validateAlgo(algo); err != nil {
		return err
	}

	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}
	defer inFile.Close()

	info, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("taille du fichier d'entrée: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s est un répertoire", inputPath)
	}

	out, err := newAtomicFile(outputPath)
	if err != nil {
		return err
	}
	defer out.cleanup()

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("génération du sel: %w", err)
	}

	h := &header{
		Version: currentVersion,
		Algo:    algo,
		Argon:   defaultArgonParams(),
		Salt:    salt,
	}
	if opts.Compress {
		h.Flags |= FlagCompressed
	}
	if _, err := out.f.Write(h.marshal()); err != nil {
		return fmt.Errorf("écriture du header: %w", err)
	}

	keys, err := deriveKeys(password, h)
	if err != nil {
		return err
	}
	defer keys.wipe()

	cipherWriter, err := initCipherWriter(writerOnly{out.f}, algo, keys)
	if err != nil {
		return err
	}

	var dst io.Writer = cipherWriter
	var gzipWriter *gzip.Writer
	if opts.Compress {
		gzipWriter, err = gzip.NewWriterLevel(cipherWriter, gzip.BestCompression)
		if err != nil {
			cipherWriter.Close()
			return fmt.Errorf("création du flux gzip: %w", err)
		}
		dst = gzipWriter
	}

	src := withProgress(inFile, info.Size(), opts.Progress)

	if _, err := io.Copy(dst, src); err != nil {
		cipherWriter.Close()
		return fmt.Errorf("chiffrement: %w", err)
	}

	// Les Close() ne sont pas différés : c'est le Close() de sio qui scelle et
	// écrit le dernier bloc. Ignorer son erreur — ce que faisait la v1 —
	// revient à annoncer « Opération réussie » sur un fichier tronqué dès que
	// le disque est plein.
	if gzipWriter != nil {
		if err := gzipWriter.Close(); err != nil {
			cipherWriter.Close()
			return fmt.Errorf("finalisation de la compression: %w", err)
		}
	}
	if err := cipherWriter.Close(); err != nil {
		return fmt.Errorf("finalisation du chiffrement: %w", err)
	}

	return out.commit()
}

// Decrypt déchiffre inputPath vers outputPath. L'algorithme, la compression
// et les paramètres Argon2 sont lus dans l'en-tête ; seul opts.Progress est
// pris en compte ici.
func Decrypt(inputPath, outputPath string, password []byte, opts Options) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}
	defer inFile.Close()

	info, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("taille du fichier d'entrée: %w", err)
	}

	h, err := readHeader(inFile)
	if err != nil {
		return err
	}

	keys, err := deriveKeys(password, h)
	if err != nil {
		return err
	}
	defer keys.wipe()

	var src io.Reader = withProgress(inFile, info.Size(), opts.Progress)

	src, err = initCipherReader(src, h.Algo, keys)
	if err != nil {
		return err
	}

	if h.compressed() {
		gzipReader, err := gzip.NewReader(src)
		if err != nil {
			return fmt.Errorf("création du flux gzip: %w", err)
		}
		defer gzipReader.Close()
		src = gzipReader
	}

	out, err := newAtomicFile(outputPath)
	if err != nil {
		return err
	}
	defer out.cleanup()

	if _, err := io.Copy(out.f, src); err != nil {
		return fmt.Errorf("déchiffrement: %w", err)
	}

	return out.commit()
}

// Inspect lit l'en-tête d'un .chto sans le déchiffrer, pour que l'interface
// puisse annoncer les paramètres réels du fichier avant de demander le mot de
// passe.
func Inspect(path string) (version byte, algo string, kdf string, compressed bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", "", false, fmt.Errorf("lecture: %w", err)
	}
	defer f.Close()

	h, err := readHeader(f)
	if err != nil {
		return 0, "", "", false, err
	}
	return h.Version, AlgoName(h.Algo), "argon2id  " + h.Argon.String(), h.compressed(), nil
}

// DefaultKDFLabel décrit les paramètres Argon2 utilisés pour les nouveaux
// fichiers, à afficher dans l'interface.
func DefaultKDFLabel() string {
	return "argon2id  " + defaultArgonParams().String()
}

func withProgress(r io.Reader, total int64, fn func(done, total int64)) io.Reader {
	if fn == nil {
		return r
	}
	return &progressReader{r: r, total: total, fn: fn}
}

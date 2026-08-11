package pkg

import (
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/minio/sio"
)

// Options regroupe les réglages d'une opération. Elle remplace la série de
// booléens positionnels de la v1, où -chacha et -parano pouvaient se
// contredire sans que personne ne le signale.
type Options struct {
	// Algo vaut AlgoAES, AlgoChaCha ou AlgoCascade. Zéro équivaut à AlgoAES.
	// Ignoré au déchiffrement : l'algorithme est lu dans l'en-tête du fichier.
	Algo byte

	// Comp vaut CompNone, CompGzip ou CompZstd. Ignoré au déchiffrement :
	// l'algorithme est lu dans l'en-tête du fichier.
	Comp byte

	// Pad masque la taille réelle du clair en insérant du remplissage jusqu'au
	// palier supérieur (voir pad.go). Exige une taille d'entrée connue et
	// s'exclut avec la compression. Ignoré au déchiffrement.
	Pad bool

	// Progress, si non nil, est appelé au fil de la copie avec le nombre
	// d'octets d'entrée déjà traités et la taille totale de l'entrée. Un total
	// nul signifie « taille inconnue » — c'est le cas d'une entrée lue sur un
	// flux.
	Progress func(done, total int64)
}

// validate attrape les combinaisons impossibles avant d'écrire quoi que ce soit.
func (o Options) validate() error {
	if err := validateComp(o.Comp); err != nil {
		return err
	}
	if o.Pad && o.Comp != CompNone {
		return errors.New("le remplissage et la compression s'excluent : la taille d'un fichier compressé dépend de la compressibilité du contenu, que le remplissage ne masque pas")
	}
	return nil
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

// Registre des temporaires en cours d'écriture. Un defer ne s'exécute pas
// quand le processus reçoit SIGINT : sans ce registre, un Ctrl+C laisserait
// un .chto-tmp-* orphelin dans le répertoire de l'utilisateur.
var (
	pendingMu sync.Mutex
	pending   = map[string]struct{}{}
)

// CleanupTemporaries supprime les temporaires encore en cours d'écriture.
// À appeler depuis un gestionnaire de signal. RemoveAll et non Remove : une
// extraction de dossier travaille dans un répertoire temporaire.
func CleanupTemporaries() {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	for p := range pending {
		os.RemoveAll(p)
		delete(pending, p)
	}
}

func trackTemp(p string) {
	pendingMu.Lock()
	pending[p] = struct{}{}
	pendingMu.Unlock()
}

func untrackTemp(p string) {
	pendingMu.Lock()
	delete(pending, p)
	pendingMu.Unlock()
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
	trackTemp(f.Name())
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
	untrackTemp(a.f.Name())

	// Le rename doit être rendu durable lui aussi : les données sont sur le
	// disque après le Sync, mais l'entrée de répertoire ne l'est pas forcément.
	// Une coupure de courant juste après pourrait laisser la destination
	// absente. Best effort : tous les systèmes ne permettent pas d'ouvrir un
	// répertoire (Windows), et l'échec ici n'invalide pas l'écriture.
	if dir, err := os.Open(filepath.Dir(a.dest)); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// cleanup s'appelle en defer : sans commit, le temporaire disparaît.
func (a *atomicFile) cleanup() {
	if a.committed {
		return
	}
	a.f.Close()
	os.Remove(a.f.Name())
	untrackTemp(a.f.Name())
}

// atomicDir est le pendant d'atomicFile pour l'extraction d'un dossier :
// l'archive est déroulée dans un répertoire temporaire voisin, qui n'est
// renommé sur la destination qu'une fois l'extraction complète et
// authentifiée. Un fichier falsifié en fin d'archive ne laisse donc pas un
// dossier à moitié extrait sous le nom attendu.
type atomicDir struct {
	path      string
	dest      string
	committed bool
}

func newAtomicDir(dest string) (*atomicDir, error) {
	// Un rename de dossier échoue si la destination existe déjà (et n'est pas
	// un dossier vide) : autant le dire tout de suite, et clairement.
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%s existe déjà : déplace-le ou renomme-le avant d'extraire", dest)
	}
	p, err := os.MkdirTemp(filepath.Dir(dest), ".chto-tmp-*")
	if err != nil {
		return nil, fmt.Errorf("création du dossier temporaire: %w", err)
	}
	if err := os.Chmod(p, 0700); err != nil {
		os.RemoveAll(p)
		return nil, fmt.Errorf("permissions du dossier temporaire: %w", err)
	}
	trackTemp(p)
	return &atomicDir{path: p, dest: dest}, nil
}

func (a *atomicDir) commit() error {
	if err := os.Rename(a.path, a.dest); err != nil {
		return fmt.Errorf("renommage vers %s: %w", a.dest, err)
	}
	a.committed = true
	untrackTemp(a.path)
	return nil
}

func (a *atomicDir) cleanup() {
	if a.committed {
		return
	}
	os.RemoveAll(a.path)
	untrackTemp(a.path)
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

// Note sur sio.AES_GCM : la constante s'appelait AES_256_GCM jusqu'à la
// v0.4.3, elle a été renommée en v0.5.0 parce que la suite accepte aussi des
// clés de 128 bits. Ici les clés font toujours 32 octets, c'est donc bien de
// l'AES-256-GCM. La valeur écrite dans le format n'a pas changé (0), les
// fichiers restent interchangeables entre les deux versions de la librairie.

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
			CipherSuites: []byte{sio.AES_GCM},
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
			CipherSuites: []byte{sio.AES_GCM},
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
			CipherSuites: []byte{sio.AES_GCM},
		})

	case AlgoChaCha:
		return sio.DecryptReader(src, sio.Config{
			Key:          keys.Key,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		})

	case AlgoAES:
		return sio.DecryptReader(src, sio.Config{
			Key:          keys.Key,
			CipherSuites: []byte{sio.AES_GCM},
		})

	default:
		return nil, fmt.Errorf("algorithme inconnu : %d", algo)
	}
}

// --- Couche de compression ---------------------------------------------

// zstdLevel : le niveau 3 est le compromis retenu. Au-delà, zstd devient
// nettement plus lent pour quelques pour cent de taille, ce qui annulerait la
// raison même de le préférer à gzip.
const zstdLevel = zstd.SpeedDefault

// initCompressWriter monte la couche de compression au-dessus de dst. Le writer
// renvoyé est nil quand aucune compression n'est demandée, ce qui évite au
// reste du code de distinguer les deux cas.
func initCompressWriter(dst io.Writer, comp byte) (io.WriteCloser, error) {
	switch comp {
	case CompNone:
		return nil, nil
	case CompGzip:
		w, err := gzip.NewWriterLevel(dst, gzip.BestCompression)
		if err != nil {
			return nil, fmt.Errorf("création du flux gzip: %w", err)
		}
		return w, nil
	case CompZstd:
		// writerOnly : l'encodeur zstd ne doit pas refermer la couche de
		// chiffrement sous lui, c'est nous qui ordonnons les Close().
		w, err := zstd.NewWriter(writerOnly{dst}, zstd.WithEncoderLevel(zstdLevel))
		if err != nil {
			return nil, fmt.Errorf("création du flux zstd: %w", err)
		}
		return w, nil
	default:
		return nil, validateComp(comp)
	}
}

// initCompressReader monte la couche de décompression au-dessus de src et
// renvoie de quoi la relâcher.
func initCompressReader(src io.Reader, comp byte) (io.Reader, func(), error) {
	switch comp {
	case CompNone:
		return src, func() {}, nil
	case CompGzip:
		r, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, fmt.Errorf("création du flux gzip: %w", err)
		}
		return r, func() { r.Close() }, nil
	case CompZstd:
		// Un seul goroutine de décodage : le flux est déjà séquentiel et la
		// concurrence par défaut de zstd ne ferait que consommer de la mémoire.
		d, err := zstd.NewReader(src, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, nil, fmt.Errorf("création du flux zstd: %w", err)
		}
		return d.IOReadCloser(), func() { d.Close() }, nil
	default:
		return nil, nil, validateComp(comp)
	}
}

// --- API publique ------------------------------------------------------

// source décrit ce qu'on chiffre : un dossier déjà parcouru, ou un flux
// d'octets dont la taille est connue (fichier) ou non (entrée standard).
type source struct {
	plan *archivePlan
	r    io.Reader
	// size est la taille du clair, ou -1 quand elle est inconnue.
	size int64
}

// payloadSize renvoie la taille exacte de la charge utile qui sera chiffrée, et
// si elle est connue. Pour un dossier, c'est la taille du tar, en-têtes compris.
func (s source) payloadSize() (int64, bool, error) {
	if s.plan != nil {
		n, err := tarSize(s.plan)
		if err != nil {
			return 0, false, err
		}
		return n, true, nil
	}
	if s.size < 0 {
		return 0, false, nil
	}
	return s.size, true, nil
}

// Encrypt chiffre inputPath vers outputPath. inputPath peut être un fichier ou
// un dossier : dans ce second cas, l'arborescence est empaquetée en tar au fil
// du chiffrement et le drapeau FlagArchive est posé dans l'en-tête. Le fichier
// produit est toujours au format v3.
func Encrypt(inputPath, outputPath string, password []byte, opts Options) error {
	info, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}

	var src source
	// Le scan du dossier a lieu avant la création de la sortie : une
	// arborescence refusée n'y laisse donc aucun fichier partiel.
	if info.IsDir() {
		plan, err := scanDirectory(inputPath)
		if err != nil {
			return err
		}
		src = source{plan: plan, size: plan.total}
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s n'est ni un fichier régulier ni un dossier", inputPath)
	} else {
		inFile, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("lecture: %w", err)
		}
		defer inFile.Close()
		src = source{r: inFile, size: info.Size()}
	}

	out, err := newAtomicFile(outputPath)
	if err != nil {
		return err
	}
	defer out.cleanup()

	if err := encrypt(out.f, src, password, opts); err != nil {
		return err
	}
	return out.commit()
}

// EncryptStream chiffre src vers dst sans passer par le disque. size est la
// taille du clair, ou -1 si elle est inconnue — auquel cas la progression n'a
// pas de total et le remplissage n'est pas possible.
//
// Aucune écriture atomique ici : sur un tube, il n'y a pas de retour en
// arrière. C'est à l'appelant de ne pas diriger un flux vers un fichier qu'il
// tient à conserver.
func EncryptStream(dst io.Writer, src io.Reader, size int64, password []byte, opts Options) error {
	return encrypt(dst, source{r: src, size: size}, password, opts)
}

// encrypt monte la chaîne d'écriture (remplissage → compression → chiffrement)
// et l'exécute. Tous les chemins de chiffrement passent par ici.
func encrypt(dst io.Writer, src source, password []byte, opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	algo := opts.Algo
	if algo == 0 {
		algo = AlgoAES
	}
	if err := validateAlgo(algo); err != nil {
		return err
	}

	// Le remplissage doit être décidé avant l'écriture de l'en-tête : sa
	// longueur est inscrite en tête de la charge utile, et on ne revient pas en
	// arrière dans un flux.
	var padding int64
	if opts.Pad {
		payload, known, err := src.payloadSize()
		if err != nil {
			return err
		}
		if !known {
			return errors.New("le remplissage exige une taille d'entrée connue : impossible sur un flux")
		}
		padding = paddingFor(payload)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("génération du sel: %w", err)
	}

	h := &header{
		Version: currentVersion,
		Algo:    algo,
		Argon:   defaultArgonParams(),
		Comp:    opts.Comp,
		Salt:    salt,
	}
	if src.plan != nil {
		h.Flags |= FlagArchive
	}
	if opts.Pad {
		h.Flags |= FlagPadded
	}
	if _, err := dst.Write(h.marshal()); err != nil {
		return fmt.Errorf("écriture du header: %w", err)
	}

	keys, err := deriveKeys(password, h)
	if err != nil {
		return err
	}
	defer keys.wipe()

	cipherWriter, err := initCipherWriter(writerOnly{dst}, algo, keys)
	if err != nil {
		return err
	}

	compWriter, err := initCompressWriter(cipherWriter, opts.Comp)
	if err != nil {
		cipherWriter.Close()
		return err
	}
	var payloadDst io.Writer = cipherWriter
	if compWriter != nil {
		payloadDst = compWriter
	}

	if opts.Pad {
		if err := writePadding(payloadDst, padding); err != nil {
			cipherWriter.Close()
			return err
		}
	}

	if src.plan != nil {
		if err := writeArchive(payloadDst, src.plan, opts.Progress); err != nil {
			cipherWriter.Close()
			return err
		}
	} else {
		total := src.size
		if total < 0 {
			total = 0
		}
		if _, err := io.Copy(payloadDst, withProgress(src.r, total, opts.Progress)); err != nil {
			cipherWriter.Close()
			return fmt.Errorf("chiffrement: %w", err)
		}
	}

	// Les Close() ne sont pas différés : c'est le Close() de sio qui scelle et
	// écrit le dernier bloc. Ignorer son erreur — ce que faisait la v1 —
	// revient à annoncer « Opération réussie » sur un fichier tronqué dès que
	// le disque est plein.
	if compWriter != nil {
		if err := compWriter.Close(); err != nil {
			cipherWriter.Close()
			return fmt.Errorf("finalisation de la compression: %w", err)
		}
	}
	if err := cipherWriter.Close(); err != nil {
		return fmt.Errorf("finalisation du chiffrement: %w", err)
	}
	return nil
}

// Decrypt déchiffre inputPath vers outputPath. L'algorithme, la compression, le
// remplissage, la nature du contenu (fichier ou dossier) et les paramètres
// Argon2 sont lus dans l'en-tête ; seul opts.Progress est pris en compte ici.
//
// Si le fichier contient un dossier, outputPath est créé comme dossier et
// l'arborescence y est extraite. outputPath ne doit alors pas déjà exister.
func Decrypt(inputPath, outputPath string, password []byte, opts Options) error {
	inFile, size, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Le flux est monté avant que la sortie n'existe : un en-tête invalide ou
	// un mauvais mot de passe échoue donc sans rien créer.
	src, h, closeSrc, err := openDecrypted(inFile, size, password, opts)
	if err != nil {
		return err
	}
	defer closeSrc()

	if h.archive() {
		out, err := newAtomicDir(outputPath)
		if err != nil {
			return err
		}
		defer out.cleanup()

		if err := extractArchive(src, out.path); err != nil {
			return err
		}
		return out.commit()
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

// DecryptStream déchiffre src vers dst. Quand le fichier contient un dossier,
// c'est le flux tar lui-même qui est écrit : il n'y a rien à extraire sur un
// tube, et `| tar xf -` fait le reste.
//
// Comme EncryptStream, sans écriture atomique — et le clair sort au fil de
// l'eau, donc avant que l'authentification de la fin du fichier soit connue.
// Acceptable vers un tube, jamais vers un fichier qu'on tient à conserver.
func DecryptStream(dst io.Writer, src io.Reader, password []byte, opts Options) error {
	r, _, closeSrc, err := openDecrypted(src, 0, password, opts)
	if err != nil {
		return err
	}
	defer closeSrc()

	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("déchiffrement: %w", err)
	}
	return nil
}

// Verify contrôle qu'un fichier est intact et déchiffrable, sans rien écrire
// sur le disque : tout part vers io.Discard. Utile pour vérifier une
// sauvegarde sans avoir la place — ou l'envie — de l'extraire.
func Verify(inputPath string, password []byte, opts Options) error {
	inFile, size, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()
	return verify(inFile, size, password, opts)
}

// VerifyStream est Verify sur un flux, pour contrôler une sauvegarde qui arrive
// par un tube sans jamais la poser sur le disque.
func VerifyStream(src io.Reader, password []byte, opts Options) error {
	return verify(src, 0, password, opts)
}

func verify(in io.Reader, size int64, password []byte, opts Options) error {
	src, h, closeSrc, err := openDecrypted(in, size, password, opts)
	if err != nil {
		return err
	}
	defer closeSrc()

	// Pour une archive, on déroule le tar plutôt que de jeter les octets en
	// vrac : ça contrôle aussi que l'extraction serait acceptée, donc qu'une
	// sauvegarde de dossier est réellement restaurable.
	if h.archive() {
		if err := checkArchive(src); err != nil {
			return fmt.Errorf("vérification: %w", err)
		}
		return nil
	}

	if _, err := io.Copy(io.Discard, src); err != nil {
		return fmt.Errorf("vérification: %w", err)
	}
	return nil
}

// openInput ouvre un .chto et renvoie sa taille, pour que la progression ait un
// total.
func openInput(path string) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("lecture: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("taille du fichier d'entrée: %w", err)
	}
	return f, info.Size(), nil
}

// openDecrypted monte la chaîne de lecture (déchiffrement → décompression →
// saut du remplissage) et renvoie de quoi la refermer. Partagé par tous les
// chemins de lecture pour qu'ils ne puissent pas diverger. Un total nul
// signifie que la taille d'entrée est inconnue.
func openDecrypted(in io.Reader, total int64, password []byte, opts Options) (io.Reader, *header, func(), error) {
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func(err error) (io.Reader, *header, func(), error) {
		closeAll()
		return nil, nil, nil, err
	}

	h, err := readHeader(in)
	if err != nil {
		return fail(err)
	}

	keys, err := deriveKeys(password, h)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, keys.wipe)

	// L'en-tête a déjà été consommé : le compteur ne verra que ce qui reste,
	// il faut donc l'ôter du total pour que la progression atteigne 100 %.
	restant := total - int64(len(h.Raw))
	if total <= 0 {
		restant = 0
	}
	src, err := initCipherReader(withProgress(in, restant, opts.Progress), h.Algo, keys)
	if err != nil {
		return fail(err)
	}

	src, releaseComp, err := initCompressReader(src, h.Comp)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, releaseComp)

	// Le remplissage est en tête de la charge utile : le sauter ici, une fois
	// pour toutes, évite que chaque appelant ait à y penser.
	if h.padded() {
		if err := skipPadding(src); err != nil {
			return fail(err)
		}
	}

	return src, h, closeAll, nil
}

// Details décrit un .chto tel que son en-tête l'annonce.
type Details struct {
	Version    byte
	Algo       string
	KDF        string
	Compressed bool
	// Comp nomme l'algorithme de compression ("aucune", "gzip", "zstd").
	Comp string
	// Archive vaut true quand le fichier contient un dossier : le
	// déchiffrement produira une arborescence, pas un fichier.
	Archive bool
	// Padded vaut true quand la taille réelle du clair est masquée par du
	// remplissage.
	Padded bool
}

// Inspect lit l'en-tête d'un .chto sans le déchiffrer, pour que l'interface
// puisse annoncer les paramètres réels du fichier avant de demander le mot de
// passe.
func Inspect(path string) (Details, error) {
	f, err := os.Open(path)
	if err != nil {
		return Details{}, fmt.Errorf("lecture: %w", err)
	}
	defer f.Close()

	h, err := readHeader(f)
	if err != nil {
		return Details{}, err
	}
	return Details{
		Version:    h.Version,
		Algo:       AlgoName(h.Algo),
		KDF:        "argon2id  " + h.Argon.String(),
		Compressed: h.compressed(),
		Comp:       CompName(h.Comp),
		Archive:    h.archive(),
		Padded:     h.padded(),
	}, nil
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

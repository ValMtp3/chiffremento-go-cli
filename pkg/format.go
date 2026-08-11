package pkg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Format de fichier .chto
//
//	magic       8   "CHFRMT03"
//	version     1   1 et 2 (anciens), 3 (courant)
//	flags       1   bit0 = compressé (v1/v2), bit1 = archive tar, bit2 = rempli
//	algoID      1   1=AES-GCM, 2=ChaCha20-Poly1305, 3=Cascade
//	--- v2 et v3 --------------------------------------------
//	argonTime   4   uint32 big-endian
//	argonMemory 4   uint32 big-endian, en KiB
//	argonPar    1   uint8
//	--- v3 uniquement ---------------------------------------
//	compAlgo    1   0=aucune, 1=gzip, 2=zstd
//	---------------------------------------------------------
//	salt       16
//
// Le magic est resté identique d'une version à l'autre : c'est l'octet de
// version qui aiguille la lecture. Changer le magic aurait fait échouer les
// anciens fichiers avant même qu'on puisse lire leur version.
//
// La v3 remplace le drapeau de compression par un champ : un booléen sur un bit
// ne pouvait pas distinguer gzip de zstd, et empiler un bit par algorithme
// rendait possibles des états contradictoires. En v1 et v2, bit0 signifiait
// gzip — c'est le seul sens qu'il ait jamais eu, donc la relecture est directe.
const (
	magicNumber = "CHFRMT03"
	magicSize   = len(magicNumber)

	versionSize  = 1
	flagsSize    = 1
	algoIDSize   = 1
	compAlgoSize = 1
	saltSize     = 16

	argonParamsSize = 4 + 4 + 1

	headerSizeV1 = magicSize + versionSize + flagsSize + algoIDSize + saltSize // 27
	headerSizeV2 = headerSizeV1 + argonParamsSize                              // 36
	headerSizeV3 = headerSizeV2 + compAlgoSize                                 // 37

	versionV1      = byte(1)
	versionV2      = byte(2)
	versionV3      = byte(3)
	currentVersion = versionV3
)

// Drapeaux du header. Tout bit non listé dans knownFlags est refusé à la
// lecture : ça garde la place libre pour de futures options sans qu'un vieux
// binaire n'interprète un fichier récent de travers.
const (
	// FlagCompressed n'est plus écrit depuis la v3, où compAlgo fait foi. Il
	// reste lu pour les fichiers v1 et v2, où il signifie gzip.
	FlagCompressed = byte(1 << 0)
	// FlagArchive : la charge utile est un tar, produit à partir d'un dossier.
	// Un binaire antérieur refusera le fichier au lieu d'écrire un tar brut
	// sous un nom de dossier, puisque tout bit inconnu est rejeté.
	FlagArchive = byte(1 << 1)
	// FlagPadded : la charge utile commence par un en-tête de remplissage
	// (voir pad.go), destiné à masquer la taille réelle du clair.
	FlagPadded = byte(1 << 2)
	knownFlags = FlagCompressed | FlagArchive | FlagPadded
)

// Algorithmes de compression, tels qu'inscrits dans le champ compAlgo de la v3.
const (
	CompNone = byte(0)
	CompGzip = byte(1)
	CompZstd = byte(2)
)

// CompName rend un algorithme de compression lisible pour l'interface.
func CompName(c byte) string {
	switch c {
	case CompNone:
		return "aucune"
	case CompGzip:
		return "gzip"
	case CompZstd:
		return "zstd"
	default:
		return "inconnue"
	}
}

func validateComp(c byte) error {
	switch c {
	case CompNone, CompGzip, CompZstd:
		return nil
	default:
		return fmt.Errorf("algorithme de compression inconnu : %d", c)
	}
}

// Identifiants d'algorithme.
const (
	AlgoAES     = byte(1)
	AlgoChaCha  = byte(2)
	AlgoCascade = byte(3)
)

// Paramètres Argon2id des nouveaux fichiers. ~144 ms par dérivation sur une
// machine de bureau récente : imperceptible pour l'utilisateur, onze fois plus
// cher que la v1 pour un attaquant. Ils sont écrits dans le header, donc ce
// choix reste ajustable sans casser les fichiers déjà produits.
const (
	defaultArgonTime    = uint32(3)
	defaultArgonMemory  = uint32(256 * 1024) // KiB
	defaultArgonThreads = uint8(4)
	argonKeyLen         = uint32(32)
)

// Paramètres figés de la v1, conservés uniquement pour relire les anciens .chto.
const (
	legacyArgonTime    = uint32(3)
	legacyArgonMemory  = uint32(32 * 1024)
	legacyArgonThreads = uint8(4)
)

// Bornes appliquées aux paramètres lus dans un header. Sans elles, un .chto
// hostile annonçant argonMemory = 4 TiB ferait exploser la RAM de la victime.
const (
	maxArgonMemory  = uint32(2 * 1024 * 1024) // KiB, soit 2 GiB
	maxArgonTime    = uint32(16)
	maxArgonThreads = uint8(16)
)

var (
	errBadMagic  = errors.New("format inconnu : ce fichier n'a pas été produit par chiffremento")
	errTruncated = errors.New("fichier tronqué : header incomplet")
)

type argonParams struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

func defaultArgonParams() argonParams {
	return argonParams{Time: defaultArgonTime, Memory: defaultArgonMemory, Threads: defaultArgonThreads}
}

func legacyArgonParams() argonParams {
	return argonParams{Time: legacyArgonTime, Memory: legacyArgonMemory, Threads: legacyArgonThreads}
}

// validate refuse les paramètres hors bornes, qu'ils viennent d'un fichier
// hostile ou d'une future version mal configurée.
func (p argonParams) validate() error {
	switch {
	case p.Time == 0 || p.Time > maxArgonTime:
		return fmt.Errorf("paramètre Argon2 hors bornes : time=%d (attendu 1..%d)", p.Time, maxArgonTime)
	case p.Memory == 0 || p.Memory > maxArgonMemory:
		return fmt.Errorf("paramètre Argon2 hors bornes : memory=%d KiB (attendu 1..%d)", p.Memory, maxArgonMemory)
	case p.Threads == 0 || p.Threads > maxArgonThreads:
		return fmt.Errorf("paramètre Argon2 hors bornes : parallelism=%d (attendu 1..%d)", p.Threads, maxArgonThreads)
	}
	return nil
}

// String rend les paramètres lisibles pour l'interface (ex. "m=256MiB t=3 p=4").
func (p argonParams) String() string {
	return fmt.Sprintf("m=%dMiB t=%d p=%d", p.Memory/1024, p.Time, p.Threads)
}

// header est la représentation en mémoire de l'en-tête d'un .chto.
//
// Raw contient les octets exacts tels qu'ils sont (ou seront) sur le disque.
// En v2 ils entrent dans le calcul de la clé via HKDF, ce qui authentifie
// l'en-tête : modifier un seul octet change la clé, donc le déchiffrement
// échoue proprement sur l'authentification AEAD.
type header struct {
	Version byte
	Flags   byte
	Algo    byte
	Argon   argonParams
	// Comp est l'algorithme de compression. En v1 et v2 il est déduit de
	// FlagCompressed, en v3 il est lu dans le champ compAlgo.
	Comp byte
	Salt []byte
	Raw  []byte
}

func (h *header) compressed() bool { return h.Comp != CompNone }
func (h *header) archive() bool    { return h.Flags&FlagArchive != 0 }
func (h *header) padded() bool     { return h.Flags&FlagPadded != 0 }

// AlgoName rend un identifiant d'algorithme lisible pour l'interface.
func AlgoName(algo byte) string {
	switch algo {
	case AlgoAES:
		return "aes-256-gcm"
	case AlgoChaCha:
		return "chacha20-poly1305"
	case AlgoCascade:
		return "cascade chacha20 + aes-256-gcm"
	default:
		return "inconnu"
	}
}

func validateAlgo(algo byte) error {
	switch algo {
	case AlgoAES, AlgoChaCha, AlgoCascade:
		return nil
	default:
		return fmt.Errorf("algorithme inconnu dans le header : %d", algo)
	}
}

// marshal sérialise l'en-tête et mémorise le résultat dans h.Raw.
func (h *header) marshal() []byte {
	buf := make([]byte, 0, headerSizeV3)
	buf = append(buf, magicNumber...)
	buf = append(buf, h.Version, h.Flags, h.Algo)
	if h.Version >= versionV2 {
		buf = binary.BigEndian.AppendUint32(buf, h.Argon.Time)
		buf = binary.BigEndian.AppendUint32(buf, h.Argon.Memory)
		buf = append(buf, h.Argon.Threads)
	}
	if h.Version >= versionV3 {
		buf = append(buf, h.Comp)
	}
	buf = append(buf, h.Salt...)
	h.Raw = buf
	return buf
}

// prefixSize couvre magic + version + flags + algo : la partie commune à
// toutes les versions, celle qui nous dit combien d'octets il reste à lire.
const prefixSize = magicSize + versionSize + flagsSize + algoIDSize

// readHeader lit et valide un en-tête. Toute anomalie est signalée
// explicitement : pas de repli silencieux sur des valeurs par défaut.
func readHeader(r io.Reader) (*header, error) {
	prefix := make([]byte, prefixSize)
	if err := readFull(r, prefix); err != nil {
		return nil, err
	}

	if string(prefix[:magicSize]) != magicNumber {
		return nil, errBadMagic
	}

	h := &header{
		Version: prefix[magicSize],
		Flags:   prefix[magicSize+versionSize],
		Algo:    prefix[magicSize+versionSize+flagsSize],
	}

	var remaining int
	switch h.Version {
	case versionV1:
		remaining = saltSize
	case versionV2:
		remaining = argonParamsSize + saltSize
	case versionV3:
		remaining = argonParamsSize + compAlgoSize + saltSize
	default:
		return nil, fmt.Errorf("version de format non supportée : %d (ce binaire lit les versions %d à %d)",
			h.Version, versionV1, versionV3)
	}

	rest := make([]byte, remaining)
	if err := readFull(r, rest); err != nil {
		return nil, err
	}

	if h.Version == versionV1 {
		h.Argon = legacyArgonParams()
	} else {
		h.Argon = argonParams{
			Time:    binary.BigEndian.Uint32(rest[0:4]),
			Memory:  binary.BigEndian.Uint32(rest[4:8]),
			Threads: rest[8],
		}
	}

	// Avant la v3, la compression était un unique bit et signifiait gzip.
	if h.Version >= versionV3 {
		h.Comp = rest[argonParamsSize]
	} else if h.Flags&FlagCompressed != 0 {
		h.Comp = CompGzip
	}
	h.Salt = rest[remaining-saltSize:]
	h.Raw = append(prefix, rest...)

	if err := h.finalize(); err != nil {
		return nil, err
	}
	return h, nil
}

func readFull(r io.Reader, buf []byte) error {
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errTruncated
		}
		return fmt.Errorf("lecture du header: %w", err)
	}
	return nil
}

// finalize applique les validations communes à toutes les versions.
func (h *header) finalize() error {
	if err := validateAlgo(h.Algo); err != nil {
		return err
	}
	if h.Flags&^knownFlags != 0 {
		return fmt.Errorf("drapeaux inconnus dans le header : 0x%02x", h.Flags&^knownFlags)
	}
	if err := validateComp(h.Comp); err != nil {
		return err
	}
	// En v3, la compression est décrite par compAlgo seul. Un fichier qui porte
	// les deux est contradictoire : soit il a été bricolé, soit il vient d'un
	// producteur bogué. Dans les deux cas on refuse plutôt que de choisir.
	if h.Version >= versionV3 && h.Flags&FlagCompressed != 0 {
		return errors.New("header incohérent : drapeau de compression v1/v2 sur un fichier v3")
	}
	// Le remplissage n'existe pas avant la v3 : un vieux fichier qui l'annonce
	// serait relu de travers, ses premiers octets pris pour un en-tête de
	// remplissage.
	if h.Version < versionV3 && h.padded() {
		return fmt.Errorf("header incohérent : drapeau de remplissage sur un fichier v%d", h.Version)
	}
	return h.Argon.validate()
}

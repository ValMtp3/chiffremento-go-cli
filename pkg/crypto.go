package pkg

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/minio/sio"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Configuration Argon2 et format de fichier
const (
	argonTime    = 3
	argonMemory  = 32 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltSize     = 16

	magicNumber       = "CHFRMT03"
	magicSize         = len(magicNumber)
	versionSize       = 1
	flagsSize         = 1
	algoIDSize        = 1
	maxRecursionDepth = 2
	chunkSize         = 64 * 1024
	headerSize        = magicSize + versionSize + flagsSize + algoIDSize + saltSize

	currentVersion = byte(1)

	flags          = 0
	FlagCompressed = 1 << 0

	AlgoAES     = byte(1)
	AlgoChaCha  = byte(2)
	AlgoCascade = byte(3)
)

// --- Fonctions Helper ---

// deriveKey génère une clé de 32 bytes via Argon2id.
func deriveKey(password []byte, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}

func deriveSubPassword(masterPassword []byte) (innerPw, outerPw []byte) {
	hash := sha256.New

	hkdfStream := hkdf.New(hash, masterPassword, nil, []byte("chiffrement-cascade"))

	innerPw = make([]byte, 32)
	outerPw = make([]byte, 32)

	io.ReadFull(hkdfStream, innerPw)
	io.ReadFull(hkdfStream, outerPw)

	return innerPw, outerPw
}

type cascadeWriteCloser struct {
	inner io.WriteCloser
	outer io.WriteCloser
}

func (c *cascadeWriteCloser) Write(p []byte) (n int, err error) {
	return c.inner.Write(p)
}

func (c *cascadeWriteCloser) Close() error {
	errInner := c.inner.Close()
	errOuter := c.outer.Close()
	if errInner != nil {
		return errInner
	}
	return errOuter
}

func initCipherWriter(dst io.Writer, algoID byte, key, innerKey, outerKey []byte) (io.WriteCloser, error) {
	switch algoID {
	case AlgoCascade:
		// Mode Cascade : ChaCha (Externe) et AES (Interne)
		outerConfig := sio.Config{
			Key:          outerKey,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		}
		outerWriter, err := sio.EncryptWriter(dst, outerConfig)
		if err != nil {
			return nil, fmt.Errorf("création flux externe: %w", err)
		}

		innerConfig := sio.Config{
			Key:          innerKey,
			CipherSuites: []byte{sio.AES_256_GCM},
		}
		innerWriter, err := sio.EncryptWriter(outerWriter, innerConfig)
		if err != nil {
			outerWriter.Close()
			return nil, fmt.Errorf("création flux interne: %w", err)
		}

		return &cascadeWriteCloser{inner: innerWriter, outer: outerWriter}, nil

	case AlgoChaCha:
		config := sio.Config{
			Key:          key,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		}
		return sio.EncryptWriter(dst, config)

	default: // AlgoAES
		config := sio.Config{
			Key:          key,
			CipherSuites: []byte{sio.AES_256_GCM},
		}
		return sio.EncryptWriter(dst, config)
	}
}

func initCipherReader(src io.Reader, algoID byte, key, innerKey, outerKey []byte) (io.Reader, error) {
	switch algoID {
	case AlgoCascade:
		// 1. Outer Layer (ChaCha)
		outerConfig := sio.Config{
			Key:          outerKey,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		}
		outerReader, err := sio.DecryptReader(src, outerConfig)
		if err != nil {
			return nil, fmt.Errorf("init déchiffrement externe: %w", err)
		}

		// 2. Inner Layer (AES)
		innerConfig := sio.Config{
			Key:          innerKey,
			CipherSuites: []byte{sio.AES_256_GCM},
		}
		return sio.DecryptReader(outerReader, innerConfig)

	case AlgoChaCha:
		config := sio.Config{
			Key:          key,
			CipherSuites: []byte{sio.CHACHA20_POLY1305},
		}
		return sio.DecryptReader(src, config)

	default: // AlgoAES
		config := sio.Config{
			Key:          key,
			CipherSuites: []byte{sio.AES_256_GCM},
		}
		return sio.DecryptReader(src, config)
	}
}

// --- Fonctions Principales ---

// Encrypt
func Encrypt(inputPath string, outputPath string, password []byte, compressData bool, useChaCha bool, useParano bool) error {
	// A. OUVERTURE DES FICHIERS
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	defer outFile.Close()

	// B. PRÉPARATION DU HEADER (SEL & CLÉ)
	// 1. On génère le sel pour Argon2
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("génération du sel: %w", err)
	}

	// 2. Préparation des clés
	var key, innerKey, outerKey []byte

	if useParano {
		innerPw, outerPw := deriveSubPassword(password)
		innerKey, err = deriveKey(innerPw, salt)
		if err != nil {
			return fmt.Errorf("dérivation clé interne: %w", err)
		}
		outerKey, err = deriveKey(outerPw, salt)
		if err != nil {
			return fmt.Errorf("dérivation clé externe: %w", err)
		}
	} else {
		key, err = deriveKey(password, salt)
		if err != nil {
			return fmt.Errorf("dérivation de clé: %w", err)
		}
	}

	// C. ÉCRITURE DU HEADER

	var currentFlags byte
	if compressData {
		currentFlags |= FlagCompressed
	}

	algoID := AlgoAES
	if useChaCha {
		algoID = AlgoChaCha
	}
	if useParano {
		algoID = AlgoCascade
	}

	// Écritures
	if _, err := outFile.Write([]byte(magicNumber)); err != nil {
		return err
	}
	if _, err := outFile.Write([]byte{currentVersion}); err != nil {
		return err
	}
	if _, err := outFile.Write([]byte{currentFlags}); err != nil {
		return err
	}
	if _, err := outFile.Write([]byte{algoID}); err != nil {
		return err
	}
	if _, err := outFile.Write(salt); err != nil {
		return err
	}

	// D. Configuration SIO
	var finalWriter io.Writer

	encryptedWriter, err := initCipherWriter(outFile, algoID, key, innerKey, outerKey)
	if err != nil {
		return err
	}
	defer encryptedWriter.Close()
	finalWriter = encryptedWriter

	if compressData {
		gzipWriter, err := gzip.NewWriterLevel(finalWriter, gzip.BestCompression)
		if err != nil {
			return fmt.Errorf("création du flux gzip: %w", err)
		}
		defer gzipWriter.Close()
		finalWriter = gzipWriter
	}

	// G. La Copie finale (streaming)
	if _, err := io.Copy(finalWriter, inFile); err != nil {
		return fmt.Errorf("streaming copy: %w", err)
	}

	return nil
}

// Decrypt
func Decrypt(inputPath string, outputPath string, password []byte) error {
	// 1. OUVERTURE DES FICHIERS
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	defer outFile.Close()

	// 2. Lecture du header
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(inFile, header); err != nil {
		return fmt.Errorf("lecture du header: %w", err)
	}

	if string(header[:magicSize]) != magicNumber {
		return fmt.Errorf("magic number invalide")
	}

	flags := header[magicSize+versionSize]
	algoID := header[magicSize+versionSize+flagsSize]
	saltOffset := magicSize + versionSize + flagsSize + algoIDSize
	salt := header[saltOffset : saltOffset+saltSize]

	// 3. Préparation des clés et déchiffrement
	var key, innerKey, outerKey []byte
	var finalReader io.Reader

	if algoID == AlgoCascade {
		innerPw, outerPw := deriveSubPassword(password)
		innerKey, err = deriveKey(innerPw, salt)
		if err != nil {
			return fmt.Errorf("clé interne: %w", err)
		}
		outerKey, err = deriveKey(outerPw, salt)
		if err != nil {
			return fmt.Errorf("clé externe: %w", err)
		}
	} else {
		key, err = deriveKey(password, salt)
		if err != nil {
			return fmt.Errorf("clé: %w", err)
		}
	}

	finalReader, err = initCipherReader(inFile, algoID, key, innerKey, outerKey)
	if err != nil {
		return err
	}

	if flags&FlagCompressed != 0 {
		gzipReader, err := gzip.NewReader(finalReader)
		if err != nil {
			return fmt.Errorf("création du flux gzip: %w", err)
		}
		defer gzipReader.Close()
		finalReader = gzipReader
	}

	// G. La Copie finale (streaming)
	if _, err := io.Copy(outFile, finalReader); err != nil {
		return fmt.Errorf("streaming copy: %w", err)
	}

	return nil
}

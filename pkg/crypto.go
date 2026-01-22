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

	// 2. On transforme le mot de passe en clé de 32 bytes
	key, err := deriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("dérivation de clé: %w", err)
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

	//D. Configuration SIO
	config := sio.Config{
		Key: key,
	}

	if useChaCha {
		config.CipherSuites = []byte{sio.CHACHA20_POLY1305}
	} else {
		config.CipherSuites = []byte{sio.AES_256_GCM}
	}

	// E. Création du flux chiffré
	encryptedWriter, err := sio.EncryptWriter(outFile, config)
	if err != nil {
		return fmt.Errorf("création du flux chiffré: %w", err)
	}
	defer encryptedWriter.Close()

	var finalWriter io.Writer = encryptedWriter

	if compressData {
		gzipWriter, err := gzip.NewWriterLevel(encryptedWriter, gzip.BestCompression)
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
	saltOffset := magicSize + versionSize + flagsSize + algoIDSize
	salt := header[saltOffset : saltOffset+saltSize]

	// 3. Dérivation clé
	key, err := deriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("clé: %w", err)
	}

	// 4. COnfig SIO
	config := sio.Config{
		Key: key,
	}

	//5. Création flux déchiffré
	decryptedReader, err := sio.DecryptReader(inFile, config)
	if err != nil {
		return fmt.Errorf("création du flux déchiffré: %w", err)
	}

	var finalReader io.Reader = decryptedReader

	if flags&FlagCompressed != 0 {
		gzipReader, err := gzip.NewReader(decryptedReader)
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

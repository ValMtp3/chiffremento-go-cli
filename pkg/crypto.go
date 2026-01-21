package pkg

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Configuration Argon2 et format de fichier
const (
	argonTime    = 3
	argonMemory  = 32 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltSize     = 16
	nonceSize    = 12

	magicNumber       = "CHFRMT03"
	magicSize         = 8
	versionSize       = 1
	flagsSize         = 1
	algoIDSize        = 1
	maxRecursionDepth = 2
	chunkSize         = 64 * 1024
	headerSize        = magicSize + versionSize + flagsSize + algoIDSize + saltSize + nonceSize

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

// addPadding ajoute des octets aléatoires pour masquer la taille réelle du fichier.
func addPadding(data []byte) ([]byte, error) {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("taille padding: %w", err)
	}
	paddingSize := int(b[0])
	if paddingSize == 0 {
		paddingSize = 13
	}
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("contenu padding: %w", err)
	}
	padding[paddingSize-1] = byte(paddingSize)
	return append(data, padding...), nil
}

// removePadding retire et valide le padding ajouté.
func removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("données vides")
	}
	paddingSize := int(data[len(data)-1])
	if paddingSize > len(data) || paddingSize == 0 {
		return nil, fmt.Errorf("padding invalide")
	}
	return data[:len(data)-paddingSize], nil
}

// Helpers GZIP
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// initCipher initialise le moteur de chiffrement (AES-GCM ou ChaCha20-Poly1305).
func initCipher(algoID byte, key []byte) (cipher.AEAD, error) {
	switch algoID {
	case AlgoAES, AlgoCascade:
		if algoID == AlgoCascade {
			return chacha20poly1305.New(key)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("création AES: %w", err)
		}
		return cipher.NewGCM(block)

	case AlgoChaCha:
		return chacha20poly1305.New(key)

	default:
		return nil, fmt.Errorf("algorithme inconnu: %d", algoID)
	}
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

func encryptStream(src io.Reader, dst io.Writer, password []byte, algoID byte, flags byte) error {
	// 1. Génération des aléas (Salt + Nonce)
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("salt %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce %w", err)
	}

	// 2. Dérivation de la clé
	key, err := deriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	// 3. Initialisation du moteur crypto
	engineAlgo := algoID
	if algoID == AlgoCascade {
		engineAlgo = AlgoChaCha
	}
	aead, err := initCipher(engineAlgo, key)
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}

	// 4. Écriture de l'En-tête (Header)
	if _, err := dst.Write([]byte(magicNumber)); err != nil {
		return err
	}
	if _, err := dst.Write([]byte{currentVersion}); err != nil {
		return err
	}
	if _, err := dst.Write([]byte{flags}); err != nil {
		return err
	}
	if _, err := dst.Write([]byte{algoID}); err != nil {
		return err
	}
	if _, err := dst.Write(salt); err != nil {
		return err
	}
	if _, err := dst.Write(nonce); err != nil {
		return err
	}

	// 5. Boucle de lecture/écriture par chunks
	buf := make([]byte, chunkSize)

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)

			chunkLen := uint16(len(ciphertext))
			if err := binary.Write(dst, binary.BigEndian, chunkLen); err != nil {
				return fmt.Errorf("write chunk len: %w", err)
			}
			if _, err := dst.Write(ciphertext); err != nil {
				return fmt.Errorf("write chunk len: %w", err)
			}

			incNonce(nonce)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read error: %w", readErr)
		}
	}

	return nil
}

func decryptStream(src io.Reader, dst io.Writer, password []byte) error {
	// 1. Lecture de l'En-tête complet
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("lecture header: %w", err)
	}

	// 2. Analyse de l'en-tête
	if string(header[:magicSize]) != magicNumber {
		return fmt.Errorf("magic number invalide")
	}

	algoID := header[magicSize+versionSize+flagsSize]

	offset := magicSize + versionSize + flagsSize + algoIDSize
	salt := header[offset : offset+saltSize]
	offset += saltSize
	nonce := header[offset : offset+nonceSize]

	// 3. Dérivation de la clé
	key, err := deriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	// 4. Initialisation Moteur
	engineAlgo := algoID
	if algoID == AlgoCascade {
		engineAlgo = AlgoChaCha
	}
	aead, err := initCipher(engineAlgo, key)
	if err != nil {
		return fmt.Errorf("cipher init: %w", err)
	}

	// 5. Boucle de déchiffrement
	lenBuf := make([]byte, 2)

	for {
		// A. Lire la taille du prochain chunk
		if _, err := io.ReadFull(src, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("lecture taille chunk: %w", err)
		}
		chunkLen := binary.BigEndian.Uint16(lenBuf)

		// B. Lire le contenu chiffré
		chunkCipher := make([]byte, chunkLen)
		if _, err := io.ReadFull(src, chunkCipher); err != nil {
			return fmt.Errorf("lecture body chunk: %w", err)
		}

		// C. Déchiffrer
		plaintext, err := aead.Open(nil, nonce, chunkCipher, nil)
		if err != nil {
			return fmt.Errorf("déchiffrement chunk: %w", err)
		}

		// D. Écrire le clair
		if _, err := dst.Write(plaintext); err != nil {
			return fmt.Errorf("ecriture sortie: %w", err)
		}

		// E. Incrementer le Nonce
		incNonce(nonce)
	}
	return nil
}

// --- Fonctions Principales ---

// Encrypt
func Encrypt(inputPath string, outputPath string, password []byte, compressData bool, useChaCha bool, useParano bool) error {
	// 1. Ouverture du fichier d'entrée (Lecture)
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}
	defer inFile.Close()

	// 2. Création du fichier (écriture)
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	defer outFile.Close()

	algo := AlgoAES
	if useChaCha {
		algo = AlgoChaCha
	}

	err = encryptStream(inFile, outFile, password, algo, 0)

	if err != nil {
		return fmt.Errorf("streaming: %w", err)
	}

	return nil
}

// Decrypt
func Decrypt(inputPath string, outputPath string, password []byte) error {
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

	err = decryptStream(inFile, outFile, password)

	if err != nil {
		return err
	}

	return nil
}

func incNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

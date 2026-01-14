package pkg

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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

	magicNumber = "CHFRMT03"
	magicSize   = 8
	versionSize = 1
	flagsSize   = 1
	algoIDSize  = 1
	headerSize  = magicSize + versionSize + flagsSize + algoIDSize + saltSize + nonceSize

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

// sealData gère le processus bas niveau : génération sel/nonce, dérivation clé, chiffrement et assemblage.
func sealData(data []byte, password []byte, algoID byte, flags byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}

	engineAlgo := algoID
	if algoID == AlgoCascade {
		engineAlgo = AlgoChaCha
	}

	aead, err := initCipher(engineAlgo, key)
	if err != nil {
		return nil, fmt.Errorf("cipher init: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Construction du fichier final : [Magic][Version][Flags][Algo][Salt][Nonce][Ciphertext]
	output := make([]byte, 0, headerSize+len(ciphertext))
	output = append(output, []byte(magicNumber)...)
	output = append(output, currentVersion)
	output = append(output, flags)
	output = append(output, algoID)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return output, nil
}

// --- Fonctions Principales ---

// Encrypt orchestre la lecture, la préparation (compression/padding) et le chiffrement (standard ou parano).
func Encrypt(inputPath string, outputPath string, password []byte, compressData bool, useChaCha bool, useParano bool) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}

	// 1. Préparation des données (Compression + Padding)
	currentFlags := byte(0)
	if compressData {
		data, err = compress(data)
		if err != nil {
			return fmt.Errorf("compression: %w", err)
		}
		currentFlags |= FlagCompressed
	}

	data, err = addPadding(data)
	if err != nil {
		return fmt.Errorf("padding: %w", err)
	}

	// 2. Chiffrement selon le mode
	var finalOutput []byte

	if useParano {
		innerPw, outerPw := deriveSubPassword(password)

		// Mode Cascade : Chiffrement AES (Interne) -> Chiffrement ChaCha (Externe)
		layer1, err := sealData(data, innerPw, AlgoAES, currentFlags)
		if err != nil {
			return fmt.Errorf("layer1 aes: %w", err)
		}

		finalOutput, err = sealData(layer1, outerPw, AlgoCascade, 0)
		if err != nil {
			return fmt.Errorf("layer2 cascade: %w", err)
		}

	} else {
		// Mode Standard (Simple couche)
		algo := AlgoAES
		if useChaCha {
			algo = AlgoChaCha
		}
		finalOutput, err = sealData(data, password, algo, currentFlags)
		if err != nil {
			return fmt.Errorf("chiffrement: %w", err)
		}
	}

	if err := os.WriteFile(outputPath, finalOutput, 0644); err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	return nil
}

// Decrypt point d'entrée pour le déchiffrement.
func Decrypt(inputPath string, outputPath string, password []byte) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}

	plaintext, err := decryptBytes(data, password)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	return nil
}

// decryptBytes analyse l'en-tête, déchiffre et gère la récursivité (Mode Cascade).
func decryptBytes(data []byte, password []byte) ([]byte, error) {
	// 1. Validation de l'en-tête
	if len(data) < headerSize {
		return nil, fmt.Errorf("fichier trop petit pour être valide manque le header")
	}
	if string(data[:magicSize]) != magicNumber {
		return nil, fmt.Errorf("magic number invalide")
	}

	fileVersion := data[magicSize]

	if fileVersion < currentVersion {
		fmt.Fprintf(os.Stderr, "⚠️  Attention : Version de fichier obsolète (v%d). Pensez à rechiffrer ce fichier avec la version actuelle (v%d).\n", fileVersion, currentVersion)
	} else if fileVersion > currentVersion {
		return nil, fmt.Errorf("version de fichier trop récente (v%d), mettez à jour chiffrermento", fileVersion)
	}
	flags := data[magicSize+versionSize]
	algoID := data[magicSize+versionSize+flagsSize]

	headerOffset := magicSize + versionSize + flagsSize + algoIDSize
	salt := data[headerOffset : headerOffset+saltSize]
	headerOffset += saltSize
	nonce := data[headerOffset : headerOffset+nonceSize]
	ciphertext := data[headerSize:]

	var innerPw, outerPw []byte

	if algoID == AlgoCascade {
		innerPw, outerPw = deriveSubPassword(password)
	}

	// 2. Dérivation & Initialisation

	var key []byte
	var err error

	if algoID == AlgoCascade {
		key, err = deriveKey(outerPw, salt)
	} else {
		key, err = deriveKey(password, salt)
	}

	if err != nil {
		return nil, err
	}

	engineAlgo := algoID
	if algoID == AlgoCascade {
		engineAlgo = AlgoChaCha
	}

	aead, err := initCipher(engineAlgo, key)
	if err != nil {
		return nil, err
	}

	// 3. Déchiffrement du payload
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("déchiffrement échoué: %w", err)
	}

	// 4. Gestion de la récursivité (Mode Parano/Cascade)
	if algoID == AlgoCascade {
		return decryptBytes(plaintext, innerPw)
	}

	// 5. Post-traitement (Padding + Décompression)
	plaintext, err = removePadding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("remove padding: %w", err)
	}

	if flags&FlagCompressed != 0 {
		plaintext, err = decompress(plaintext)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
	}

	return plaintext, nil
}

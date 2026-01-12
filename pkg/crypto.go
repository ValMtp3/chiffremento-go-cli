package pkg

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
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
	AlgoCascade = byte(3) // Nouveau mode Parano
)

// --- Fonctions Helper ---

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

func addPadding(data []byte) ([]byte, error) {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("taille padding: %w", err)
	}
	paddingSize := int(b[0])
	if paddingSize == 0 {
		paddingSize = 13 // Arbitraire si 0
	}
	padding := make([]byte, paddingSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("contenu padding: %w", err)
	}
	padding[paddingSize-1] = byte(paddingSize)
	return append(data, padding...), nil
}

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

func initCipher(algoID byte, key []byte) (cipher.AEAD, error) {
	switch algoID {
	case AlgoAES, AlgoCascade: // Cascade utilise AES pour la couche interne, ou ChaCha pour l'externe, à gérer par l'appelant
		// Ici on initialise juste l'algo demandé par le header.
		// Si le header dit "AES", on donne AES.
		// Pour le mode Cascade, le header externe dira "Cascade" (qu'on traitera comme ChaCha),
		// et le header interne dira "AES".

		// Note : Par convention, on va dire que si on demande AlgoCascade au niveau chiffrement 'technique',
		// on utilise ChaCha20 comme couche externe.
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

// sealData : La fonction "Cuisine" qui chiffre un blob d'octets
func sealData(data []byte, password []byte, algoID byte, flags byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}

	// Pour sealData, si on demande Cascade, on utilise ChaCha comme moteur de chiffrement
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

	// Construction Header + Output
	output := make([]byte, 0, headerSize+len(ciphertext))
	output = append(output, []byte(magicNumber)...)
	output = append(output, currentVersion)
	output = append(output, flags)
	output = append(output, algoID) // Ici on met le VRAI ID (donc potentiellement AlgoCascade)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return output, nil
}

// --- Fonctions Principales ---

func Encrypt(inputPath string, outputPath string, password []byte, compressData bool, useChaCha bool, useParano bool) error {
	// 1. Lecture
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("lecture: %w", err)
	}

	// 2. Préparation (Compression + Padding)
	// Ces étapes ne se font qu'une seule fois, sur les données claires.
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

	// 3. Chiffrement
	var finalOutput []byte

	if useParano {
		// Mode Parano : Double couche (Oignon)
		// Couche 1 : AES (Interne)
		layer1, err := sealData(data, password, AlgoAES, currentFlags)
		if err != nil {
			return fmt.Errorf("layer1 aes: %w", err)
		}

		// Couche 2 : ChaCha (Externe) marqué comme "Cascade"
		// On passe flags=0 car la compression/padding est déjà encapsulée dans layer1
		finalOutput, err = sealData(layer1, password, AlgoCascade, 0)
		if err != nil {
			return fmt.Errorf("layer2 cascade: %w", err)
		}

	} else {
		// Mode Standard
		algo := AlgoAES
		if useChaCha {
			algo = AlgoChaCha
		}
		finalOutput, err = sealData(data, password, algo, currentFlags)
		if err != nil {
			return fmt.Errorf("chiffrement: %w", err)
		}
	}

	// 4. Écriture
	if err := os.WriteFile(outputPath, finalOutput, 0644); err != nil {
		return fmt.Errorf("écriture: %w", err)
	}
	return nil
}

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

// decryptBytes : Fonction récursive capable de peler l'oignon
func decryptBytes(data []byte, password []byte) ([]byte, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("trop court")
	}
	if string(data[:magicSize]) != magicNumber {
		return nil, fmt.Errorf("magic number invalide")
	}

	// Parsing Header
	// version := data[magicSize] (on ignore la vérif version pour simplifier ici)
	flags := data[magicSize+versionSize]
	algoID := data[magicSize+versionSize+flagsSize]

	headerOffset := magicSize + versionSize + flagsSize + algoIDSize
	salt := data[headerOffset : headerOffset+saltSize]
	headerOffset += saltSize
	nonce := data[headerOffset : headerOffset+nonceSize]
	ciphertext := data[headerSize:]

	// Dérivation & Init
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	// Si l'algo est Cascade, on utilise ChaCha pour déchiffrer cette couche
	engineAlgo := algoID
	if algoID == AlgoCascade {
		engineAlgo = AlgoChaCha
	}

	aead, err := initCipher(engineAlgo, key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("déchiffrement échoué: %w", err)
	}

	// Logique Récursive (Parano)
	if algoID == AlgoCascade {
		// Le plaintext est LUI-MÊME un fichier chiffré (couche AES interne)
		// On appelle récursivement decryptBytes
		return decryptBytes(plaintext, password)
	}

	// Traitement final (Standard)
	// 1. Retrait Padding
	plaintext, err = removePadding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("remove padding: %w", err)
	}

	// 2. Décompression
	if flags&FlagCompressed != 0 {
		plaintext, err = decompress(plaintext)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
	}

	return plaintext, nil
}

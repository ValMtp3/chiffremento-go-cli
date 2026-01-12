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
	FlagReserved1  = 1 << 1
	FlagReserved2  = 1 << 2

	AlgoAES    = byte(1)
	AlgoChaCha = byte(2)
)

func deriveKey(password []byte, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, saltSize)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}
	}
	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}

func addPadding(data []byte) ([]byte, error) {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("génération taille padding: %w", err)
	}
	paddingSize := int(b[0])
	if paddingSize == 0 {
		paddingSize = 13
	}
	padding := make([]byte, paddingSize)

	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("génération contenu padding: %w", err)
	}
	padding[paddingSize-1] = byte(paddingSize)

	return append(data, padding...), nil
}

func removePadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("données vides, impossible de retirer le padding")
	}
	paddingSize := int(data[len(data)-1])
	if paddingSize > len(data) || paddingSize == 0 {
		return nil, fmt.Errorf("taille de padding invalide")
	}
	return data[:len(data)-paddingSize], nil
}

func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(data)
	if err != nil {
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
	case AlgoAES:
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

func Encrypt(inputPath string, outputPath string, password []byte, compressData bool, useChaCha bool) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("lecture fichier: %w", err)
	}
	currentFlags := byte(0)
	if compressData {
		data, err = compress(data)
		if err != nil {
			return fmt.Errorf("compression: %w", err)
		}
		currentFlags |= FlagCompressed
	}
	selectedAlgo := AlgoAES
	if useChaCha {
		selectedAlgo = AlgoChaCha
	}
	data, err = addPadding(data)
	if err != nil {
		return fmt.Errorf("ajout padding: %w", err)
	}
	salt := make([]byte, saltSize)
	_, err = rand.Read(salt)
	if err != nil {
		return fmt.Errorf("génération salt: %w", err)
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("dérivation clé: %w", err)
	}
	aead, err := initCipher(selectedAlgo, key)
	if err != nil {
		return fmt.Errorf("création cipher : %w", err)
	}
	nonce := make([]byte, nonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return fmt.Errorf("génération nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, data, nil)

	output := make([]byte, 0, headerSize+len(ciphertext))
	output = append(output, []byte(magicNumber)...)
	output = append(output, currentVersion)
	output = append(output, currentFlags)
	output = append(output, selectedAlgo)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	err = os.WriteFile(outputPath, output, 0644)
	if err != nil {
		return fmt.Errorf("écriture fichier: %w", err)
	}

	return nil
}

func Decrypt(inputPath string, outputPath string, password []byte) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("lecture fichier: %w", err)
	}

	if len(data) < headerSize {
		return fmt.Errorf("fichier trop petit: doit contenir au moins %d bytes", headerSize)
	}
	if string(data[:magicSize]) != magicNumber {
		return fmt.Errorf("Fichier non chiffré ou chiffré via un autre outil")
	}
	versionFichier := data[magicSize]

	if versionFichier != currentVersion {
		return fmt.Errorf("version de fichier non supportée: %d (attendu: %d)", versionFichier, currentVersion)
	}
	headerOffset := magicSize + versionSize + flagsSize + algoIDSize
	fileFlags := data[magicSize+versionSize]
	fileAlgo := data[magicSize+versionSize+flagsSize]
	salt := data[headerOffset : headerOffset+saltSize]
	headerOffset += saltSize
	nonce := data[headerOffset : headerOffset+nonceSize]
	ciphertext := data[headerSize:]

	key, err := deriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("dérivation clé: %w", err)
	}

	// Initialisation du bon algo de chiffrement
	aead, err := initCipher(fileAlgo, key)
	if err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}

	// Déchiffrement
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("décryptage: %w", err)
	}

	// Post-traitement (Padding puis Decompression)
	plaintext, err = removePadding(plaintext)
	if err != nil {
		return fmt.Errorf("retrait padding: %w", err)
	}

	if fileFlags&FlagCompressed != 0 {
		plaintext, err = decompress(plaintext)
		if err != nil {
			return fmt.Errorf("décompression: %w", err)
		}
	}

	err = os.WriteFile(outputPath, plaintext, 0644)
	if err != nil {
		return fmt.Errorf("écriture fichier: %w", err)
	}
	return nil
}

package pkg

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

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

}

// Decrypt
func Decrypt(inputPath string, outputPath string, password []byte) error {

}

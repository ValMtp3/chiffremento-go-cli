package pkg

import (
	"bytes"
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	originalContent := []byte("Ceci est un test de chiffrement avec Chiffremento!")
	password := []byte("motdepassetest123")

	inputFile := "test_input.txt"
	encryptedFile := "test_encrypted.bin"
	decryptedFile := "test_decrypted.txt"

	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	err := os.WriteFile(inputFile, originalContent, 0644)
	if err != nil {
		t.Fatalf("Création fichier test: %v", err)
	}

	err = Encrypt(inputFile, encryptedFile, password, false, false)
	if err != nil {
		t.Fatalf("Erreur chiffrement: %v", err)
	}

	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Fatal("Fichier chiffré non créé")
	}

	err = Decrypt(encryptedFile, decryptedFile, password)
	if err != nil {
		t.Fatalf("Erreur déchiffrement: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Lecture fichier déchiffré: %v", err)
	}

	if !bytes.Equal(originalContent, decryptedContent) {
		t.Errorf("Contenu différent!\nOriginal: %s\nDéchiffré: %s", originalContent, decryptedContent)
	}

	t.Log("✅ Test réussi: chiffrement et déchiffrement fonctionnent (sans compression)")
}

func TestEncryptDecryptCompressed(t *testing.T) {
	// Contenu répétitif pour tester l'efficacité de la compression
	originalContent := bytes.Repeat([]byte("Donnée répétitive pour bien compresser. "), 100)
	password := []byte("compressiontest123")

	inputFile := "test_comp_input.txt"
	encryptedFile := "test_comp_encrypted.bin"
	decryptedFile := "test_comp_decrypted.txt"

	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	err := os.WriteFile(inputFile, originalContent, 0644)
	if err != nil {
		t.Fatalf("Création fichier test: %v", err)
	}

	// Test avec compression activée
	err = Encrypt(inputFile, encryptedFile, password, true, false)
	if err != nil {
		t.Fatalf("Erreur chiffrement avec compression: %v", err)
	}

	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Fatal("Fichier chiffré compressé non créé")
	}

	err = Decrypt(encryptedFile, decryptedFile, password)
	if err != nil {
		t.Fatalf("Erreur déchiffrement compressé: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Lecture fichier déchiffré: %v", err)
	}

	if !bytes.Equal(originalContent, decryptedContent) {
		t.Errorf("Contenu différent après compression/décompression!")
	}

	t.Log("✅ Test réussi: chiffrement et déchiffrement avec compression fonctionnent")
}

func TestDecryptWithWrongPassword(t *testing.T) {
	originalContent := []byte("Secret")
	correctPassword := []byte("correct")
	wrongPassword := []byte("incorrect")

	inputFile := "test_wrong_pwd_input.txt"
	encryptedFile := "test_wrong_pwd_encrypted.bin"
	decryptedFile := "test_wrong_pwd_decrypted.txt"

	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	os.WriteFile(inputFile, originalContent, 0644)

	err := Encrypt(inputFile, encryptedFile, correctPassword, false, false)
	if err != nil {
		t.Fatalf("Erreur chiffrement: %v", err)
	}

	err = Decrypt(encryptedFile, decryptedFile, wrongPassword)
	if err == nil {
		t.Fatal("Déchiffrement devrait échouer avec mauvais mot de passe")
	}

	t.Log("✅ Test réussi: mauvais mot de passe refusé")
}

func TestDecryptInvalidFile(t *testing.T) {
	invalidFile := "test_invalid.bin"
	outputFile := "test_invalid_out.txt"
	password := []byte("password")

	defer os.Remove(invalidFile)
	defer os.Remove(outputFile)

	os.WriteFile(invalidFile, []byte("trop court"), 0644)

	err := Decrypt(invalidFile, outputFile, password)
	if err == nil {
		t.Fatal("Déchiffrement devrait échouer avec fichier invalide")
	}

	t.Log("✅ Test réussi: fichier invalide détecté")
}

func TestEncryptDecryptChaCha(t *testing.T) {
	originalContent := []byte("Test ChaCha20-Poly1305 encryption!")
	password := []byte("chachatest123")

	inputFile := "test_chacha_input.txt"
	encryptedFile := "test_chacha_encrypted.bin"
	decryptedFile := "test_chacha_decrypted.txt"

	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	err := os.WriteFile(inputFile, originalContent, 0644)
	if err != nil {
		t.Fatalf("Création fichier test: %v", err)
	}

	// Test avec ChaCha activé
	err = Encrypt(inputFile, encryptedFile, password, false, true)
	if err != nil {
		t.Fatalf("Erreur chiffrement ChaCha: %v", err)
	}

	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Fatal("Fichier chiffré ChaCha non créé")
	}

	err = Decrypt(encryptedFile, decryptedFile, password)
	if err != nil {
		t.Fatalf("Erreur déchiffrement ChaCha: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Lecture fichier déchiffré: %v", err)
	}

	if !bytes.Equal(originalContent, decryptedContent) {
		t.Errorf("Contenu différent après ChaCha!")
	}

	t.Log("✅ Test réussi: chiffrement et déchiffrement avec ChaCha20-Poly1305 fonctionnent")
}

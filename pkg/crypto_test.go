package pkg

import (
	"bytes"
	"fmt"
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

	// Mode standard: pas de compression, pas de chacha, pas de parano (donc AES)
	err = Encrypt(inputFile, encryptedFile, password, false, false, false)
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

	t.Log("✅ Test réussi: chiffrement et déchiffrement fonctionnent (AES Standard)")
}

func TestEncryptDecryptCompressed(t *testing.T) {
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

	// Mode compression: compression=true, chacha=false, parano=false
	err = Encrypt(inputFile, encryptedFile, password, true, false, false)
	if err != nil {
		t.Fatalf("Erreur chiffrement avec compression: %v", err)
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

	if err := os.WriteFile(inputFile, originalContent, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := Encrypt(inputFile, encryptedFile, correctPassword, false, false, false)
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

	if err := os.WriteFile(invalidFile, []byte("trop court"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

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

	// Mode ChaCha: compression=false, chacha=true, parano=false
	err = Encrypt(inputFile, encryptedFile, password, false, true, false)
	if err != nil {
		t.Fatalf("Erreur chiffrement ChaCha: %v", err)
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

func TestEncryptDecryptParano(t *testing.T) {
	originalContent := []byte("Message top secret pour le mode Parano (Cascade AES+ChaCha)!")
	password := []byte("paranoidandroid42")

	inputFile := "test_parano_input.txt"
	encryptedFile := "test_parano_encrypted.bin"
	decryptedFile := "test_parano_decrypted.txt"

	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	err := os.WriteFile(inputFile, originalContent, 0644)
	if err != nil {
		t.Fatalf("Création fichier test: %v", err)
	}

	// Mode Parano: compression=false, chacha=ignored, parano=true
	err = Encrypt(inputFile, encryptedFile, password, false, false, true)
	if err != nil {
		t.Fatalf("Erreur chiffrement Parano: %v", err)
	}

	err = Decrypt(encryptedFile, decryptedFile, password)
	if err != nil {
		t.Fatalf("Erreur déchiffrement Parano (Cascade): %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Lecture fichier déchiffré: %v", err)
	}

	if !bytes.Equal(originalContent, decryptedContent) {
		t.Errorf("Contenu différent après Parano!")
	}

	t.Log("✅ Test réussi: chiffrement et déchiffrement en mode Parano (Cascade) fonctionnent")
}

func TestDeriveKey(t *testing.T) {
	password := []byte("monSecret")
	salt := make([]byte, 16) // Sel vide (tous zéros) pour la reproductibilité du test

	// 1. Test de déterminisme : deux appels identiques doivent donner la même clé
	key1, err := deriveKey(password, salt)
	if err != nil {
		t.Fatalf("deriveKey 1 failed: %v", err)
	}
	key2, err := deriveKey(password, salt)
	if err != nil {
		t.Fatalf("deriveKey 2 failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("deriveKey n'est pas déterministe ! Les clés diffèrent pour les mêmes entrées.")
	}

	// 2. Test de sensibilité au sel : changer le sel doit changer la clé
	salt2 := make([]byte, 16)
	salt2[0] = 1 // On change un bit
	key3, err := deriveKey(password, salt2)
	if err != nil {
		t.Fatalf("deriveKey 3 failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Fatal("deriveKey ignore le sel ! La clé est identique malgré un sel différent.")
	}

	t.Log("✅ Test réussi: deriveKey est robuste et déterministe")
}

func TestStreamingLargeFile(t *testing.T) {
	// Test avec un fichier de 1 Mo pour s'assurer que le streaming (chunking) fonctionne
	size := 1 * 1024 * 1024
	originalContent := make([]byte, size)
	for i := 0; i < size; i++ {
		originalContent[i] = byte(i % 256)
	}

	password := []byte("streaming123")
	inputFile := "test_stream_in.bin"
	encryptedFile := "test_stream_enc.bin"
	decryptedFile := "test_stream_out.bin"

	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	if err := os.WriteFile(inputFile, originalContent, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Encrypt (Standard AES)
	if err := Encrypt(inputFile, encryptedFile, password, false, false, false); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decrypt
	if err := Decrypt(encryptedFile, decryptedFile, password); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if !bytes.Equal(originalContent, decryptedContent) {
		t.Fatal("Streaming : Contenu déchiffré différent de l'original")
	}

	t.Log("✅ Test réussi: Streaming sur fichier > chunk size")
}

func TestProtocolSafety_Tripwire(t *testing.T) {
	// --- ÉTAT CONNU (SNAPSHOT) ---
	// Si tu modifies ces valeurs dans crypto.go, tu DOIS modifier ce test
	// ET réfléchir si ça mérite un bump de version.
	const (
		expectedVersion    = 1
		expectedHeaderSize = 27 // 8+1+1+1+16
		expectedMagic      = "CHFRMT03"
	)

	// 1. Vérification que la version n'a pas régressé
	if currentVersion < expectedVersion {
		t.Fatalf("CRITIQUE: La version du protocole a reculé ! (Code: %d, Test attend: %d)", currentVersion, expectedVersion)
	}

	// 2. LE PIÈGE : Détection de changement de structure silencieux
	structureChanged := false

	if headerSize != expectedHeaderSize {
		t.Logf("⚠️  La taille du header a changé (Avant: %d, Main: %d)", expectedHeaderSize, headerSize)
		structureChanged = true
	}

	if magicNumber != expectedMagic {
		t.Logf("⚠️  Le Magic Number a changé (Avant: %s, Main: %s)", expectedMagic, magicNumber)
		structureChanged = true
	}

	// Si la structure a changé MAIS que la version est restée la même => ERREUR
	if structureChanged && currentVersion == expectedVersion {
		t.Fatal("🛑 STOP ! Tu as modifié la structure du fichier (Header/Magic) mais tu as oublié d'incrémenter 'currentVersion' dans crypto.go !\n" +
			"-> Si c'est un changement compatible, mets à jour ce test.\n" +
			"-> Sinon, passe currentVersion à " + fmt.Sprint(expectedVersion+1))
	}
}

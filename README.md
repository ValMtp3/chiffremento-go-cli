<div align="center">
  <h1>Chiffremento CLI</h1>
  <p>
    <strong>L'outil de chiffrement ultime pour vos fichiers.</strong><br>
    The ultimate file encryption tool.
  </p>
  <p>
    <a href="#-français">🇫🇷 Français</a> •
    <a href="#-english">🇬🇧 English</a>
  </p>
</div>

---

<a id="-français"></a>

# 🇫🇷 Français

**Chiffremento CLI** est une application en ligne de commande moderne écrite en Go qui permet de chiffrer et déchiffrer des fichiers de manière sécurisée, rapide et simple.

## ✨ Fonctionnalités

- **🔐 Chiffrement Authentifié** : Utilise **AES-GCM** (par défaut) ou **ChaCha20-Poly1305**.
- **🔑 Dérivation de Clé Robuste** : Utilise **Argon2id** pour transformer votre mot de passe en clé cryptographique inviolable.
- **📦 Compression** : Support optionnel de la compression **GZIP** pour réduire la taille avant chiffrement.
- **😱 Mode Parano** : Un mode "Cascade" unique qui double-chiffre les données (AES puis ChaCha20) pour une sécurité maximale.
- **🛡️ Format Sécurisé** : En-tête binaire personnalisé incluant Magic Number, versioning, et sel aléatoire unique par fichier.
- **🕵️ Anti-Analyse** : Padding aléatoire pour masquer la taille réelle des fichiers.

## 📥 Installation Facile (Recommandé)

Le plus simple est d'utiliser le script d'installation automatique fourni (fonctionne sur macOS et Linux).

1.  Téléchargez le binaire pour votre système et le fichier `install.sh` depuis la section **Releases** de GitHub.
2.  Ouvrez un terminal dans le dossier de téléchargement.
3.  Lancez l'installation :

```bash
sh install.sh
```

Cela rendra le programme exécutable, contournera les sécurités macOS (Gatekeeper), et l'installera dans votre système (`/usr/local/bin`). Vous pourrez ensuite utiliser la commande `chiffremento` n'importe où.

### Installation via Homebrew (macOS)

Si vous préférez utiliser Homebrew :

```bash
brew tap ValMtp3/tap
brew install chiffremento
```

## 🛠 Compilation (Avancé)

Si vous êtes développeur et souhaitez compiler le projet vous-même (nécessite Go 1.25+).

### Option 1 : Via Makefile (Recommandé)

```bash
# Compiler pour le système actuel
make build

# Compiler pour toutes les plateformes (Linux, Mac, Windows)
make build-all

# Installer globalement
make install
```

### Option 2 : Manuelle

```bash
go build -ldflags="-s -w" -o chiffremento main.go
```

## 🚀 Utilisation

L'outil s'utilise via la ligne de commande.

### Syntaxe Générale

```bash
chiffremento -mode <enc|dec> -in <fichier_entrée> -out <fichier_sortie> -key <mot_de_passe> [options]
```

### Flags Disponibles

| Flag | Description |
| :--- | :--- |
| `-mode` | **Obligatoire.** Mode d'opération (`enc` pour chiffrer, `dec` pour déchiffrer). |
| `-in` | **Obligatoire.** Chemin du fichier d'entrée. |
| `-out` | **Obligatoire.** Chemin du fichier de sortie. |
| `-key` | **Obligatoire.** Mot de passe. |
| `-comp` | *(Chiffrement)* Active la compression GZIP. |
| `-chacha`| *(Chiffrement)* Utilise ChaCha20-Poly1305 au lieu d'AES-GCM. |
| `-parano`| *(Chiffrement)* Mode Parano : Double chiffrement (AES + ChaCha20). |

### Exemples

#### 1. Chiffrement Standard (AES-GCM)
```bash
chiffremento -mode enc -in document.txt -out document.enc -key "monSuperMotDePasse"
```

#### 2. Chiffrement avec Compression et ChaCha20
```bash
chiffremento -mode enc -in image.bmp -out image.enc -key "password123" -comp -chacha
```

#### 3. Mode Parano (Double Chiffrement)
```bash
chiffremento -mode enc -in secrets.txt -out secrets.parano -key "topSecret" -parano
```

#### 4. Déchiffrement
Le déchiffrement est **intelligent** : il détecte automatiquement l'algorithme, la compression et le mode utilisés grâce à l'en-tête du fichier.

```bash
chiffremento -mode dec -in document.enc -out document_clair.txt -key "monSuperMotDePasse"
```

## 🧠 Structure Technique

### Format du Fichier Chiffré
```
[MagicNumber (8 bytes)] "CHFRMT03"
[Version (1 byte)]
[Flags (1 byte)] (Compression, etc.)
[AlgoID (1 byte)] (1=AES, 2=ChaCha, 3=Cascade)
[Salt (16 bytes)] (Aléatoire pour Argon2)
[Nonce (12 bytes)] (Aléatoire pour le chiffrement)
[Ciphertext (Variable)]
```

### Tests

```bash
go test -v ./pkg
```

---
<br>

<a id="-english"></a>

# 🇬🇧 English

**Chiffremento CLI** is a modern command-line application written in Go that provides secure, fast, and simple file encryption and decryption.

## ✨ Features

- **🔐 Authenticated Encryption**: Uses **AES-GCM** (default) or **ChaCha20-Poly1305**.
- **🔑 Robust Key Derivation**: Uses **Argon2id** to transform your password into an unbreakable cryptographic key.
- **📦 Compression**: Optional **GZIP** compression support to reduce file size before encryption.
- **😱 Parano Mode**: A unique "Cascade" mode that double-encrypts data (AES then ChaCha20) for maximum security.
- **🛡️ Secure Format**: Custom binary header including Magic Number, versioning, and unique random salt per file.
- **🕵️ Anti-Analysis**: Random padding to hide the actual file size.

## 📥 Easy Installation (Recommended)

The easiest way is to use the provided automatic installation script (works on macOS and Linux).

1.  Download the binary for your system and the `install.sh` file from the **Releases** section.
2.  Open a terminal in the download folder.
3.  Run the installation:

```bash
sh install.sh
```

This will make the program executable, bypass macOS security checks (Gatekeeper), and install it on your system (`/usr/local/bin`). You can then use the `chiffremento` command anywhere.

### Installation via Homebrew (macOS)

If you prefer using Homebrew:

```bash
brew tap ValMtp3/tap
brew install chiffremento
```

## 🛠 Compilation (Advanced)

If you are a developer and want to build the project yourself (requires Go 1.25+).

### Option 1: Via Makefile (Recommended)

```bash
# Build for current system
make build

# Build for all platforms (Linux, Mac, Windows)
make build-all

# Install globally
make install
```

### Option 2: Manual

```bash
go build -ldflags="-s -w" -o chiffremento main.go
```

## 🚀 Usage

The tool is used via the command line.

### General Syntax

```bash
chiffremento -mode <enc|dec> -in <input_file> -out <output_file> -key <password> [options]
```

### Available Flags

| Flag | Description |
| :--- | :--- |
| `-mode` | **Required.** Operation mode (`enc` to encrypt, `dec` to decrypt). |
| `-in` | **Required.** Input file path. |
| `-out` | **Required.** Output file path. |
| `-key` | **Required.** Password. |
| `-comp` | *(Encryption)* Enables GZIP compression. |
| `-chacha`| *(Encryption)* Uses ChaCha20-Poly1305 instead of AES-GCM. |
| `-parano`| *(Encryption)* Parano Mode: Double encryption (AES + ChaCha20). |

### Examples

#### 1. Standard Encryption (AES-GCM)
```bash
chiffremento -mode enc -in document.txt -out document.enc -key "mySuperPassword"
```

#### 2. Encryption with Compression and ChaCha20
```bash
chiffremento -mode enc -in image.bmp -out image.enc -key "password123" -comp -chacha
```

#### 3. Parano Mode (Double Encryption)
```bash
chiffremento -mode enc -in secrets.txt -out secrets.parano -key "topSecret" -parano
```

#### 4. Decryption
Decryption is **smart**: it automatically detects the algorithm, compression, and mode used thanks to the file header.

```bash
chiffremento -mode dec -in document.enc -out clear_document.txt -key "mySuperPassword"
```

## 🧠 Technical Structure

### Encrypted File Format
```
[MagicNumber (8 bytes)] "CHFRMT03"
[Version (1 byte)]
[Flags (1 byte)] (Compression, etc.)
[AlgoID (1 byte)] (1=AES, 2=ChaCha, 3=Cascade)
[Salt (16 bytes)] (Random for Argon2)
[Nonce (12 bytes)] (Random for encryption)
[Ciphertext (Variable)]
```

### Tests

```bash
go test -v ./pkg
```

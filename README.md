# Chiffremento CLI

Chiffremento CLI est une application en ligne de commande écrite en Go qui permet de chiffrer et déchiffrer des fichiers de manière sécurisée. Elle supporte plusieurs algorithmes de chiffrement (AES-GCM, ChaCha20-Poly1305) ainsi que la compression des données.

## Fonctionnalités

- **Chiffrement Authentifié** : Utilise AES-GCM (par défaut) ou ChaCha20-Poly1305.
- **Dérivation de Clé Robuste** : Utilise Argon2id pour dériver la clé de chiffrement à partir du mot de passe.
- **Compression** : Support optionnel de la compression GZIP avant chiffrement.
- **Mode Parano** : Un mode "Cascade" qui double-chiffre les données (AES puis ChaCha20) pour une sécurité maximale.
- **Format de Fichier Sécurisé** : En-tête personnalisé incluant Magic Number, version, flags, et sel aléatoire.

## Installation Facile (Recommandé)

Le plus simple est d'utiliser le script d'installation automatique fourni (fonctionne sur macOS et Linux).

1.  Téléchargez le binaire pour votre système et le fichier `install.sh` (disponibles dans la Release).
2.  Ouvrez un terminal dans le dossier de téléchargement.
3.  Lancez l'installation :

```bash
sh install.sh
```

Cela rendra le programme exécutable, contournera les sécurités macOS (Gatekeeper), et l'installera dans votre système (`/usr/local/bin`). Vous pourrez ensuite utiliser la commande `chiffremento` n'importe où, sans le `./`.

### Installation via Homebrew (macOS)

*(Une fois le Tap configuré)*

```bash
brew tap <votre-user>/tap
brew install chiffremento
```

## Compilation (Pour les développeurs)

Assurez-vous d'avoir Go installé (version 1.25+ recommandée).

### Option 1 : Compilation via Makefile (Recommandé)

Un `Makefile` est fourni pour simplifier la compilation et le déploiement.

```bash
# Compiler pour votre système actuel (crée le binaire 'chiffremento')
make build

# Compiler pour toutes les plateformes (Linux, Mac, Windows) dans le dossier build/
make build-all

# Installer globalement (nécessite que $GOPATH/bin soit dans votre PATH)
make install
```

### Option 2 : Installation via Go Install

Si vous souhaitez installer l'outil directement dans votre `GOPATH` :

```bash
go install
```

### Option 3 : Compilation Manuelle

```bash
go build -ldflags="-s -w" -o chiffremento main.go
```

### ⚠️ Guide : Exécuter un binaire téléchargé (GitHub Releases)

Si vous avez téléchargé l'exécutable depuis GitHub au lieu de le compiler, suivez ces étapes :

#### Sur macOS (Apple Silicon ou Intel)

1.  Ouvrez votre Terminal.
2.  Rendez le fichier exécutable :
    ```bash
    cd ~/Downloads  # ou le dossier où se trouve le fichier
    chmod +x chiffremento-darwin-arm64
    ```
3.  Lancez-le une première fois :
    ```bash
    ./chiffremento-darwin-arm64
    ```
4.  **Si macOS bloque l'ouverture ("Développeur non identifié")** :
    *   Une pop-up apparaît. Cliquez sur **OK**.
    *   Allez dans **Réglages Système** > **Confidentialité et sécurité**.
    *   Faites défiler vers le bas jusqu'à la section Sécurité.
    *   Cliquez sur le bouton **"Ouvrir quand même"** (Open Anyway) à côté du message concernant `chiffremento`.
    *   Tapez votre mot de passe Mac pour valider.
    *   Relancez la commande `./chiffremento-darwin-arm64` dans le terminal.

#### Sur Linux

```bash
chmod +x chiffremento-linux-amd64
./chiffremento-linux-amd64
```

#### Sur Windows

Lancez simplement `cmd` ou `PowerShell`, allez dans le dossier et exécutez :
```cmd
.\chiffremento-windows-amd64.exe
```

## Utilisation

L'outil s'utilise via la ligne de commande avec différents flags.

### Syntaxe Générale

```bash
./chiffremento -mode <enc|dec> -in <fichier_entrée> -out <fichier_sortie> -key <mot_de_passe> [options]
```

### Flags Disponibles

- `-mode` : Mode d'opération (`enc` pour chiffrer, `dec` pour déchiffrer). **(Obligatoire)**
- `-in` : Chemin du fichier d'entrée. **(Obligatoire)**
- `-out` : Chemin du fichier de sortie. **(Obligatoire)**
- `-key` : Mot de passe pour le chiffrement/déchiffrement. **(Obligatoire)**
- `-comp` : (Chiffrement uniquement) Active la compression GZIP avant le chiffrement.
- `-chacha` : (Chiffrement uniquement) Utilise ChaCha20-Poly1305 au lieu d'AES-GCM.
- `-parano` : (Chiffrement uniquement) Mode Parano : Double chiffrement (AES + ChaCha20). Plus lent mais plus robuste.

### Exemples

#### 1. Chiffrement Standard (AES-GCM)
```bash
./chiffremento -mode enc -in document.txt -out document.enc -key "monSuperMotDePasse"
```

#### 2. Chiffrement avec Compression et ChaCha20
```bash
./chiffremento -mode enc -in image.bmp -out image.enc -key "password123" -comp -chacha
```

#### 3. Mode Parano (Double Chiffrement)
```bash
./chiffremento -mode enc -in secrets.txt -out secrets.parano -key "topSecret" -parano
```

#### 4. Déchiffrement
Le mode de déchiffrement détecte automatiquement l'algorithme et les options utilisés lors du chiffrement (compression, algo, etc.) grâce à l'en-tête du fichier. Il n'est pas nécessaire de spécifier `-comp` ou `-chacha` lors du déchiffrement.

```bash
./chiffremento -mode dec -in document.enc -out document_clair.txt -key "monSuperMotDePasse"
```

## Structure Technique

### Format du Fichier Chiffré
Le fichier binaire généré respecte la structure suivante :
```
[MagicNumber (8 bytes)] "CHFRMT03"
[Version (1 byte)]
[Flags (1 byte)] (Indique la compression, etc.)
[AlgoID (1 byte)] (1=AES, 2=ChaCha, 3=Cascade)
[Salt (16 bytes)] (Pour Argon2)
[Nonce (12 bytes)]
[Ciphertext (Variable)]
```

### Structure du Code
- `main.go` : Point d'entrée, gestion des arguments CLI.
- `pkg/crypto.go` : Implémentation de la cryptographie, compression et gestion du format de fichier.
- `pkg/crypto_test.go` : Tests unitaires et d'intégration couvrant tous les modes.

## Tests

Pour exécuter la suite de tests :

```bash
go test -v ./pkg
```

---

# Chiffremento CLI (English)

Chiffremento CLI is a command-line application written in Go that provides secure file encryption and decryption. It supports multiple encryption algorithms (AES-GCM, ChaCha20-Poly1305) as well as data compression.

## Features

- **Authenticated Encryption**: Uses AES-GCM (default) or ChaCha20-Poly1305.
- **Robust Key Derivation**: Uses Argon2id to derive the encryption key from the password.
- **Compression**: Optional support for GZIP compression before encryption.
- **Parano Mode**: A "Cascade" mode that double-encrypts data (AES then ChaCha20) for maximum security.
- **Secure File Format**: Custom header including Magic Number, version, flags, and random salt.

## Easy Installation (Recommended)

The easiest way is to use the provided automatic installation script (works on macOS and Linux).

1.  Download the binary for your system and the `install.sh` file (available in the Release).
2.  Open a terminal in the download folder.
3.  Run the installation:

```bash
sh install.sh
```

This will make the program executable, bypass macOS security checks (Gatekeeper), and install it on your system (`/usr/local/bin`). You can then use the `chiffremento` command anywhere, without the `./`.

### Installation via Homebrew (macOS)

*(Once Tap is configured)*

```bash
brew tap <your-user>/tap
brew install chiffremento
```

## Compilation (For Developers)

Ensure you have Go installed (version 1.25+ recommended).

### Option 1: Compilation via Makefile (Recommended)

A `Makefile` is provided to simplify compilation and deployment.

```bash
# Compile for your current system (creates the 'chiffremento' binary)
make build

# Compile for all platforms (Linux, Mac, Windows) in the build/ folder
make build-all

# Install globally (requires $GOPATH/bin in your PATH)
make install
```

### Option 2: Installation via Go Install

If you wish to install the tool directly into your `GOPATH`:

```bash
go install
```

### Option 3: Manual Compilation

```bash
go build -ldflags="-s -w" -o chiffremento main.go
```

### ⚠️ Guide: Running Downloaded Binaries (GitHub Releases)

If you downloaded the executable from GitHub instead of compiling it:

#### On macOS (Apple Silicon or Intel)

1.  Open your Terminal.
2.  Make the file executable:
    ```bash
    cd ~/Downloads  # or wherever the file is
    chmod +x chiffremento-darwin-arm64
    ```
3.  Run it once:
    ```bash
    ./chiffremento-darwin-arm64
    ```
4.  **If macOS blocks execution ("Unidentified Developer")**:
    *   A popup appears. Click **OK**.
    *   Go to **System Settings** > **Privacy & Security**.
    *   Scroll down to the Security section.
    *   Click **"Open Anyway"** next to the message about `chiffremento`.
    *   Enter your password/TouchID.
    *   Run the command `./chiffremento-darwin-arm64` again in the terminal.

#### On Linux

```bash
chmod +x chiffremento-linux-amd64
./chiffremento-linux-amd64
```

#### On Windows

Simply launch `cmd` or `PowerShell` and run:
```cmd
.\chiffremento-windows-amd64.exe
```

## Usage

The tool is used via the command line with various flags.

### General Syntax

```bash
./chiffremento -mode <enc|dec> -in <input_file> -out <output_file> -key <password> [options]
```

### Available Flags

- `-mode`: Operation mode (`enc` to encrypt, `dec` to decrypt). **(Required)**
- `-in`: Input file path. **(Required)**
- `-out`: Output file path. **(Required)**
- `-key`: Password for encryption/decryption. **(Required)**
- `-comp`: (Encryption only) Enables GZIP compression before encryption.
- `-chacha`: (Encryption only) Uses ChaCha20-Poly1305 instead of AES-GCM.
- `-parano`: (Encryption only) Parano Mode: Double encryption (AES + ChaCha20). Slower but more robust.

### Examples

#### 1. Standard Encryption (AES-GCM)
```bash
./chiffremento -mode enc -in document.txt -out document.enc -key "mySuperPassword"
```

#### 2. Encryption with Compression and ChaCha20
```bash
./chiffremento -mode enc -in image.bmp -out image.enc -key "password123" -comp -chacha
```

#### 3. Parano Mode (Double Encryption)
```bash
./chiffremento -mode enc -in secrets.txt -out secrets.parano -key "topSecret" -parano
```

#### 4. Decryption
The decryption mode automatically detects the algorithm and options used during encryption (compression, algo, etc.) thanks to the file header. It is not necessary to specify `-comp` or `-chacha` during decryption.

```bash
./chiffremento -mode dec -in document.enc -out clear_document.txt -key "mySuperPassword"
```

## Technical Structure

### Encrypted File Format
The generated binary file respects the following structure:
```
[MagicNumber (8 bytes)] "CHFRMT03"
[Version (1 byte)]
[Flags (1 byte)] (Indicates compression, etc.)
[AlgoID (1 byte)] (1=AES, 2=ChaCha, 3=Cascade)
[Salt (16 bytes)] (For Argon2)
[Nonce (12 bytes)]
[Ciphertext (Variable)]
```

### Code Structure
- `main.go`: Entry point, CLI argument management.
- `pkg/crypto.go`: Implementation of cryptography, compression, and file format management.
- `pkg/crypto_test.go`: Unit and integration tests covering all modes.

## Tests

To run the test suite:

```bash
go test -v ./pkg
```

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

## ✨ Nouveautés v1.1.0

- **⚡ Mode Streaming** : Utilisation mémoire constante (quelques Mo), même pour des fichiers de 100 Go.
- **📛 Extension Unique** : Tous les fichiers chiffrés portent désormais l'extension `.chto`.
- **🚀 Simplicité** : Plus besoin de spécifier le nom du fichier de sortie (`-out` supprimé).

## ✨ Fonctionnalités CORE

- **🔐 Chiffrement Authentifié** : Utilise **AES-GCM** (par défaut) ou **ChaCha20-Poly1305**.
- **🔑 Dérivation de Clé Robuste** : Utilise **Argon2id** pour transformer votre mot de passe en clé cryptographique inviolable.
- **📦 Compression** : Support optionnel de la compression **GZIP** pour réduire la taille avant chiffrement.
- **😱 Mode Parano** : Un mode "Cascade" unique qui double-chiffre les données (AES puis ChaCha20) avec des clés dérivées indépendamment (HKDF).
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

### Installation via Homebrew (macOS)

```bash
brew tap ValMtp3/homebrew-tap
brew install chiffremento
```

## 🚀 Utilisation

L'outil s'utilise via la ligne de commande. Il ajoute automatiquement l'extension `.chto` au chiffrement et la retire au déchiffrement.

### Syntaxe Générale

```bash
chiffremento -mode <enc|dec> -in <fichier_entrée> -key <mot_de_passe> [options]
```

### Flags Disponibles

| Flag | Description |
| :--- | :--- |
| `-mode` | **Obligatoire.** Mode d'opération (`enc` pour chiffrer, `dec` pour déchiffrer). |
| `-in` | **Obligatoire.** Chemin du fichier d'entrée. |
| `-key` | **Obligatoire.** Mot de passe. |
| `-comp` | *(Chiffrement)* Active la compression GZIP. |
| `-chacha`| *(Chiffrement)* Utilise ChaCha20-Poly1305 au lieu d'AES-GCM. |
| `-parano`| *(Chiffrement)* Mode Parano : Double chiffrement (AES + ChaCha20). |

### Exemples

#### 1. Chiffrement Standard (AES-GCM)
Crée `document.txt.chto` :
```bash
chiffremento -mode enc -in document.txt -key "monSuperMotDePasse"
```

#### 2. Déchiffrement
Lit `document.txt.chto` et recrée `document.txt` :
```bash
chiffremento -mode dec -in document.txt.chto -key "monSuperMotDePasse"
```
*Note : Le déchiffrement détecte automatiquement l'algo, la compression et le mode utilisé.*

#### 3. Mode Parano (Double Chiffrement + Compression)
Crée `backup.db.chto` (sûr de chez sûr) :
```bash
chiffremento -mode enc -in backup.db -key "topSecret" -parano -comp
```

---
<br>

<a id="-english"></a>

# 🇬🇧 English

**Chiffremento CLI** is a modern command-line application written in Go that provides secure, fast, and simple file encryption and decryption.

## ✨ New in v1.1.0

- **⚡ Streaming Mode**: Constant memory usage (a few MBs), even for 100GB files.
- **📛 Unique Extension**: All encrypted files now enforce the `.chto` extension.
- **🚀 Simplicity**: No need to specify output filename anymore (`-out` flag removed).

## ✨ CORE Features

- **🔐 Authenticated Encryption**: Uses **AES-GCM** (default) or **ChaCha20-Poly1305**.
- **🔑 Robust Key Derivation**: Uses **Argon2id** to transform your password into an unbreakable cryptographic key.
- **📦 Compression**: Optional **GZIP** compression support to reduce file size before encryption.
- **😱 Parano Mode**: A unique "Cascade" mode that double-encrypts data (AES then ChaCha20) with independently derived keys (HKDF).
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

### Installation via Homebrew (macOS)

```bash
brew tap ValMtp3/homebrew-tap
brew install chiffremento
```

## 🚀 Usage

The tool is used via the command line. It automatically appends the `.chto` extension for encryption and removes it for decryption.

### General Syntax

```bash
chiffremento -mode <enc|dec> -in <input_file> -key <password> [options]
```

### Available Flags

| Flag | Description |
| :--- | :--- |
| `-mode` | **Required.** Operation mode (`enc` to encrypt, `dec` to decrypt). |
| `-in` | **Required.** Input file path. |
| `-key` | **Required.** Password. |
| `-comp` | *(Encryption)* Enables GZIP compression. |
| `-chacha`| *(Encryption)* Uses ChaCha20-Poly1305 instead of AES-GCM. |
| `-parano`| *(Encryption)* Parano Mode: Double encryption (AES + ChaCha20). |

### Examples

#### 1. Standard Encryption (AES-GCM)
Creates `document.txt.chto`:
```bash
chiffremento -mode enc -in document.txt -key "mySuperPassword"
```

#### 2. Decryption
Reads `document.txt.chto` and recreates `document.txt`:
```bash
chiffremento -mode dec -in document.txt.chto -key "mySuperPassword"
```
*Note: Decryption automatically detects the algorithm, compression, and mode used.*

#### 3. Parano Mode (Double Encryption + Compression)
Creates `backup.db.chto` (ultra secure):
```bash
chiffremento -mode enc -in backup.db -key "topSecret" -parano -comp
```

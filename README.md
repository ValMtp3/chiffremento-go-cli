<div align="center">
  <h1>Chiffremento CLI</h1>
  <p>
    <strong>Chiffrement de fichiers en ligne de commande.</strong><br>
    Command-line file encryption.
  </p>
  <p>
    <a href="#-français">🇫🇷 Français</a> •
    <a href="#-english">🇬🇧 English</a>
  </p>
</div>

---

<a id="-français"></a>

# 🇫🇷 Français

**Chiffremento CLI** est un outil en ligne de commande écrit en Go pour chiffrer et déchiffrer des fichiers. Il s'utilise soit via une interface guidée, soit avec des flags pour les scripts.

```
  chiffremento chiffrement  v2.0
┌────────────────────────────────────────────────────┐
│  entrée    rapport-annuel.pdf             14.2 Mo  │
│  sortie    rapport-annuel.pdf.chto                 │
│                                                    │
│  aead      aes-256-gcm                             │
│  kdf       argon2id  m=256MiB t=3 p=4              │
│  sel       16 o aléatoires · en-tête lié à la clé  │
│                                                    │
│  ██ ██ ██ ██ ██ d6 23 76 e5 47 23 67 8b 1d         │
│  ████████████░░░░░░░░░░░░░░░░░░  42%      38 Mo/s  │
└────────────────────────────────────────────────────┘
```

## ✨ Nouveautés v2.0

- **🖥️ Interface guidée** : lancer `chiffremento` sans argument ouvre une interface qui vous guide. Les flags restent disponibles pour les scripts.
- **🛡️ Format v2** : les paramètres Argon2 sont désormais stockés dans le fichier, et l'en-tête est lié à la clé de chiffrement. Les fichiers `.chto` produits par les versions 1.x restent déchiffrables.
- **🔑 Argon2 renforcé** : 256 MiB au lieu de 32 MiB, soit environ onze fois plus coûteux pour une attaque par force brute.
- **💾 Écriture atomique** : plus aucune façon de détruire un fichier existant avec un déchiffrement raté.
- **🙈 Fin du flag `-key`** : le mot de passe n'est plus jamais passé en argument, donc il n'apparaît plus dans `ps` ni dans l'historique du shell.
- **🔍 Commande `info`** : inspecter un `.chto` sans mot de passe et sans le déchiffrer.

## ✨ Fonctionnalités

- **🔐 Chiffrement authentifié** : **AES-256-GCM** (par défaut) ou **ChaCha20-Poly1305**, en streaming via [`minio/sio`](https://github.com/minio/sio) (format DARE).
- **🔑 Dérivation de clé** : **Argon2id**, avec des paramètres inscrits dans le fichier pour pouvoir être renforcés plus tard sans casser les anciens fichiers.
- **⚡ Mémoire constante** : chiffrer un fichier de 100 Go ne consomme que quelques mégaoctets de RAM.
- **📦 Compression** : **gzip** optionnel avant chiffrement.
- **😱 Mode parano** : double chiffrement en cascade (ChaCha20 à l'extérieur, AES à l'intérieur), avec deux clés dérivées indépendamment par HKDF.
- **🔗 En-tête lié à la clé** : version, drapeaux, algorithme, paramètres Argon2 et sel entrent tous dans la dérivation. Modifier un seul octet de l'en-tête fait échouer le déchiffrement.

## 📥 Installation

### Homebrew (macOS)

```bash
brew tap ValMtp3/homebrew-tap
brew install --cask chiffremento
```

> Depuis la v2.0.0, la distribution passe par un **cask** et non plus par une formule : GoReleaser a déprécié les formules. Si vous aviez installé la v1.x, désinstallez-la d'abord avec `brew uninstall chiffremento`. Les casks sont spécifiques à macOS ; sous Linux, utilisez le script d'installation ci-dessous.

### Script d'installation (macOS et Linux)

1. Depuis la page **Releases**, téléchargez l'archive correspondant à votre système, le fichier `checksums.txt` et `install.sh`, dans le même dossier.
2. Lancez :

```bash
bash install.sh
```

Le script vérifie l'empreinte SHA-256 de l'archive avant d'installer quoi que ce soit.

### Depuis les sources

```bash
make build
```

## 🚀 Utilisation

### Interface guidée

Sans aucun argument, dans un terminal :

```bash
chiffremento
```

### Ligne de commande

```bash
chiffremento -mode <enc|dec|verify|info> -in <fichier> [options]
```

Le mot de passe **n'est jamais un argument**. Il est demandé de façon masquée, ou lu sur l'entrée standard si celle-ci n'est pas un terminal.

| Flag | Description |
| :--- | :--- |
| `-mode` | **Obligatoire.** `enc` (chiffrer), `dec` (déchiffrer), `verify` (contrôler sans rien écrire) ou `info` (inspecter l'en-tête). |
| `-in` | **Obligatoire.** Chemin du fichier d'entrée. |
| `-comp` | *(enc)* Active la compression gzip. |
| `-chacha` | *(enc)* Utilise ChaCha20-Poly1305 au lieu d'AES-GCM. |
| `-parano` | *(enc)* Double chiffrement en cascade. S'exclut avec `-chacha`. |
| `-version` | Affiche la version. |

### Exemples

Chiffrer (crée `document.txt.chto`) :

```bash
chiffremento -mode enc -in document.txt
```

Déchiffrer (recrée `document.txt`) :

```bash
chiffremento -mode dec -in document.txt.chto
```

Contrôler qu'une sauvegarde est intacte et déchiffrable, sans rien écrire sur le disque :

```bash
chiffremento -mode verify -in sauvegarde.tar.gz.chto
```

Inspecter un fichier sans le déchiffrer ni saisir de mot de passe :

```bash
chiffremento -mode info -in document.txt.chto
```

Mode parano avec compression :

```bash
chiffremento -mode enc -in backup.db -parano -comp
```

Depuis un script, le mot de passe se fournit sur l'entrée standard :

```bash
echo "$MOT_DE_PASSE" | chiffremento -mode enc -in backup.db
```

## 🗂️ Format de fichier

```
magic       8 o   "CHFRMT03"
version     1 o   1 (ancien) ou 2 (courant)
flags       1 o   bit 0 = compressé
algo        1 o   1 = AES-GCM, 2 = ChaCha20-Poly1305, 3 = cascade
argonTime   4 o   uint32 big-endian        ┐
argonMemory 4 o   uint32 big-endian (KiB)  ├ v2 uniquement
argonPar    1 o   uint8                    ┘
salt       16 o
```

La clé est dérivée en deux temps : `Argon2id(mot de passe, sel, paramètres)` puis `HKDF-Expand` avec **l'en-tête complet en info**. C'est ce qui lie l'en-tête à la clé sans champ d'authentification supplémentaire.

Les fichiers en version 1 sont relus avec leur dérivation d'origine. Les nouveaux fichiers sont toujours écrits en version 2.

## ⚠️ Modèle de menace

Ce que l'outil protège :

- le **contenu** d'un fichier au repos : disque volé, sauvegarde envoyée sur un service tiers, clé USB perdue ;
- l'**intégrité** : toute modification du contenu chiffré ou de l'en-tête est détectée, le déchiffrement échoue.

Ce que l'outil **ne** protège **pas** :

- le **nom du fichier** : `secret.pdf.chto` annonce son contenu ;
- la **taille** : elle suit celle du fichier d'origine, à quelques dizaines d'octets près ;
- les **métadonnées** : dates et permissions d'origine ne sont pas conservées ;
- avec `-comp`, la **compressibilité** du contenu fuit à travers la taille finale ;
- une **machine compromise** : keylogger, mémoire lue par un autre processus, fichier d'origine encore présent sur le disque après chiffrement.

La solidité dépend **entièrement** de la force du mot de passe. Argon2id rend chaque tentative coûteuse (~150 ms), mais un mot de passe court reste cassable. Utilisez une phrase de passe longue.

Le mode parano ne remplace pas un bon mot de passe : il protège contre la découverte d'une faiblesse dans un seul des deux algorithmes, rien d'autre.

---
<br>

<a id="-english"></a>

# 🇬🇧 English

**Chiffremento CLI** is a command-line tool written in Go for encrypting and decrypting files. It offers a guided interface, or flags for scripting.

## ✨ New in v2.0

- **🖥️ Guided interface**: running `chiffremento` with no arguments opens an interactive interface. Flags remain available for scripts.
- **🛡️ Format v2**: Argon2 parameters are now stored in the file, and the header is bound to the encryption key. `.chto` files produced by 1.x versions remain decryptable.
- **🔑 Stronger Argon2**: 256 MiB instead of 32 MiB, roughly eleven times costlier to brute-force.
- **💾 Atomic writes**: a failed decryption can no longer destroy an existing file.
- **🙈 No more `-key` flag**: the password is never passed as an argument, so it no longer appears in `ps` or shell history.
- **🔍 `info` command**: inspect a `.chto` file without a password and without decrypting it.

## ✨ Features

- **🔐 Authenticated encryption**: **AES-256-GCM** (default) or **ChaCha20-Poly1305**, streamed through [`minio/sio`](https://github.com/minio/sio) (DARE format).
- **🔑 Key derivation**: **Argon2id**, with parameters written into the file so they can be strengthened later without breaking old files.
- **⚡ Constant memory**: encrypting a 100 GB file uses only a few megabytes of RAM.
- **📦 Compression**: optional **gzip** before encryption.
- **😱 Parano mode**: cascaded double encryption (ChaCha20 outside, AES inside) with two independently derived keys via HKDF.
- **🔗 Key-bound header**: version, flags, algorithm, Argon2 parameters and salt all feed the key derivation. Changing a single header byte makes decryption fail.

## 📥 Installation

### Homebrew (macOS)

```bash
brew tap ValMtp3/homebrew-tap
brew install --cask chiffremento
```

> Since v2.0.0 distribution goes through a **cask** rather than a formula, as GoReleaser deprecated formulae. If you installed v1.x, uninstall it first with `brew uninstall chiffremento`. Casks are macOS-only; on Linux, use the install script below.

### Install script (macOS and Linux)

1. From the **Releases** page, download the archive for your system, the `checksums.txt` file and `install.sh`, into the same folder.
2. Run:

```bash
bash install.sh
```

The script verifies the archive's SHA-256 checksum before installing anything.

### From source

```bash
make build
```

## 🚀 Usage

### Guided interface

With no arguments, in a terminal:

```bash
chiffremento
```

### Command line

```bash
chiffremento -mode <enc|dec|verify|info> -in <file> [options]
```

The password is **never an argument**. It is prompted for with masked input, or read from standard input when that is not a terminal.

| Flag | Description |
| :--- | :--- |
| `-mode` | **Required.** `enc` (encrypt), `dec` (decrypt), `verify` (check without writing anything) or `info` (inspect the header). |
| `-in` | **Required.** Input file path. |
| `-comp` | *(enc)* Enables gzip compression. |
| `-chacha` | *(enc)* Uses ChaCha20-Poly1305 instead of AES-GCM. |
| `-parano` | *(enc)* Cascaded double encryption. Mutually exclusive with `-chacha`. |
| `-version` | Prints the version. |

### Examples

Encrypt (creates `document.txt.chto`):

```bash
chiffremento -mode enc -in document.txt
```

Decrypt (recreates `document.txt`):

```bash
chiffremento -mode dec -in document.txt.chto
```

Check that a backup is intact and decryptable, without writing anything to disk:

```bash
chiffremento -mode verify -in backup.tar.gz.chto
```

Inspect a file without decrypting it or entering a password:

```bash
chiffremento -mode info -in document.txt.chto
```

Parano mode with compression:

```bash
chiffremento -mode enc -in backup.db -parano -comp
```

From a script, supply the password on standard input:

```bash
echo "$PASSWORD" | chiffremento -mode enc -in backup.db
```

## 🗂️ File format

```
magic       8 B   "CHFRMT03"
version     1 B   1 (legacy) or 2 (current)
flags       1 B   bit 0 = compressed
algo        1 B   1 = AES-GCM, 2 = ChaCha20-Poly1305, 3 = cascade
argonTime   4 B   uint32 big-endian        ┐
argonMemory 4 B   uint32 big-endian (KiB)  ├ v2 only
argonPar    1 B   uint8                    ┘
salt       16 B
```

The key is derived in two steps: `Argon2id(password, salt, params)` then `HKDF-Expand` with **the full header as info**. This binds the header to the key without an extra authentication field.

Version 1 files are read back with their original derivation. New files are always written as version 2.

## ⚠️ Threat model

What this tool protects:

- the **contents** of a file at rest: stolen disk, backup uploaded to a third party, lost USB drive;
- **integrity**: any modification of the ciphertext or the header is detected and decryption fails.

What it does **not** protect:

- the **filename**: `secret.pdf.chto` advertises its own contents;
- the **size**: it tracks the original file's size within a few dozen bytes;
- **metadata**: original timestamps and permissions are not preserved;
- with `-comp`, the content's **compressibility** leaks through the final size;
- a **compromised machine**: keyloggers, memory read by another process, or the original file still sitting on disk after encryption.

Security depends **entirely** on password strength. Argon2id makes each attempt expensive (~150 ms), but a short password is still crackable. Use a long passphrase.

Parano mode is not a substitute for a good password: it guards against a weakness being found in one of the two algorithms, nothing more.

## 📄 License

MIT — see [LICENSE](LICENSE).

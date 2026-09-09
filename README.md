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
  chiffremento chiffrement  v2.1.1
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

## ✨ Nouveautés v2.1

> Le **format de fichier** est passé en v4 dans cette version. Les deux numéros sont indépendants : la version du programme suit ses fonctionnalités, celle du format sa structure binaire. `chiffremento -mode info` affiche celle d'un fichier donné.

- **📁 Dossiers** : chiffrer un dossier entier, empaqueté en tar au fil du chiffrement et recréé à l'identique au déchiffrement.
- **🗜️ zstd** : remplace gzip, mesuré ~8× plus rapide à ratio comparable. gzip n'est plus produit, seulement relu : les `.chto` v1 et v2 compressés restent déchiffrables. La compression est désormais décrite par un champ de l'en-tête plutôt que par un simple bit.
- **📏 `-pad`** : masque la taille réelle du contenu en arrondissant au palier supérieur.
- **🔗 `-out`, `-in -`, `-out -`** : destination choisie, et flux standard pour composer avec d'autres outils.
- **🗂️ Explorateur de fichiers** dans l'interface guidée, en alternative à la saisie du chemin.
- **📊 Force du mot de passe par dictionnaire** : `azerty123` est enfin annoncé comme faible.
- **🔑 Profils de dérivation** : `-kdf standard|fort|maximum`, du plus rapide au plus coûteux à attaquer.
- **🏷️ `-meta minimal`** : conserve le nom et la date d'origine à l'intérieur du chiffré, pour pouvoir sortir sous un nom neutre.
- **📊 `-mode bench`** : mesure les profils et le débit des algorithmes sur votre machine, et conseille un profil.

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
- **📁 Fichiers et dossiers** : un dossier est empaqueté en **tar** au fil du chiffrement — sans archive intermédiaire sur le disque — et recréé tel quel au déchiffrement. Les liens symboliques sont refusés, et une archive ne peut rien écrire hors du dossier de destination.
- **📦 Compression** : **zstd**, optionnelle avant chiffrement et proposée active pour un dossier. Elle remplace gzip, mesurée ~8× plus rapide pour un ratio équivalent ; les anciens fichiers gzip restent déchiffrables mais ne sont plus produits.
- **📏 Taille masquée** : option `-pad`, qui arrondit la taille au palier supérieur ([schéma Padmé](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf)) pour qu'un `.chto` ne trahisse plus la taille exacte de son contenu.
- **🔗 Composable** : `-in -` et `-out -` lisent et écrivent sur les flux standard.
- **📊 Indicateur de force réaliste** : la robustesse du mot de passe est évaluée par [`zxcvbn`](https://github.com/trustelem/zxcvbn), qui reconnaît les mots de dictionnaire, les prénoms, les dates et les suites de touches. `azerty123` est annoncé à ~13 bits, pas à ~60.
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

Elle demande l'opération, puis comment désigner la cible : **saisir un chemin** (ou le glisser-déposer), ou **parcourir les fichiers**. Dans l'explorateur, `↑↓` se déplacent, `→` entre dans un dossier et `entrée` choisit.

Les décisions suivent la même grammaire : `↑↓` parcourent les réponses, `→` (ou `entrée`) valide, `←` revient à la décision précédente — y compris d'un écran à l'autre, en gardant les réponses déjà données. Dans un champ texte et dans l'explorateur, où `←` sert déjà, le retour se fait avec `shift+tab`.

Au chiffrement, une fois le nom et la date conservés à l'intérieur du chiffré, elle propose de **brouiller ceux du fichier produit** : sortie sous un nom tiré au hasard — `3fb8db8ee5db3891.chto` — et datée du 1er janvier 2000. Le déchiffrement les restitue tous les deux. La date de *création*, elle, reste celle de l'écriture : aucun appel en espace utilisateur ne la change, le brouillage cache la date au regard ordinaire, pas à l'examen du disque.

Quand le masquage de taille est activé, elle demande aussi la **largeur du palier**, en montrant ce que chaque cran coûte sur *ce* fichier : « 7.2 Mo → environ 8.0 Mo (+11.8 %) · tout ce qui pèse de 4.0 Mo à 8.0 Mo sort identique ».

Une fois l'opération finie, elle propose enfin de **supprimer ce qu'elle remplace** : l'original après un chiffrement, le `.chto` après un déchiffrement. Effacer un original n'a lieu qu'après relecture et authentification complète du chiffré — l'original est la seule autre copie. « Garder » est toujours la réponse sous le curseur, et la suppression retire l'entrée du dossier sans effacer les données du support.

### Ligne de commande

```bash
chiffremento -mode <enc|dec|verify|info|passwd> -in <fichier> [options]
```

Le mot de passe **n'est jamais un argument**. Il est demandé de façon masquée, ou lu sur l'entrée standard si celle-ci n'est pas un terminal.

| Flag | Description |
| :--- | :--- |
| `-mode` | **Obligatoire.** `enc` (chiffrer), `dec` (déchiffrer), `verify` (contrôler sans rien écrire), `info` (inspecter l'en-tête), `passwd` (changer le mot de passe) ou `bench` (mesurer les coûts). |
| `-in` | **Obligatoire.** Fichier ou dossier d'entrée, ou `-` pour l'entrée standard. |
| `-out` | Destination. Par défaut, l'entrée suivie de `.chto` en `enc`, l'entrée sans l'extension en `dec`. `-` écrit sur la sortie standard. |
| `-comp` | *(enc)* Active la compression zstd. |
| `-pad` | *(enc)* Masque la taille réelle. S'exclut avec `-comp`. |
| `-pad-niveau` | *(enc)* Largeur du palier : `standard` (défaut), `fort` ou `maximum`. Exige `-pad`. |
| `-chacha` | *(enc)* Utilise ChaCha20-Poly1305 au lieu d'AES-GCM. |
| `-parano` | *(enc)* Double chiffrement en cascade. S'exclut avec `-chacha`. |
| `-kdf` | *(enc)* Coût de la dérivation : `standard` (défaut), `fort` ou `maximum`. |
| `-meta` | *(enc)* Métadonnées conservées : `none` (défaut) ou `minimal` (nom et date). |
| `-force` | *(enc, dec)* Écrase la destination si elle existe déjà. Sans lui, l'opération est refusée. Ne s'applique jamais à un dossier extrait. |
| `-version` | Affiche la version. |

> Une destination qui existe déjà est **refusée par défaut** : déchiffrer
> `doc.pdf.chto` à côté d'un `doc.pdf` sans rapport ne le détruit pas. Utilise
> `-force` pour écraser volontairement. Un dossier extrait ne s'écrase jamais,
> même avec `-force` : cela voudrait dire supprimer une arborescence entière.

### Exemples

Chiffrer (crée `document.txt.chto`) :

```bash
chiffremento -mode enc -in document.txt
```

Déchiffrer (recrée `document.txt`) :

```bash
chiffremento -mode dec -in document.txt.chto
```

Chiffrer un dossier (crée `photos.chto`, qui contient toute l'arborescence) :

```bash
chiffremento -mode enc -in photos
```

Le déchiffrer recrée le dossier `photos`, qui ne doit pas déjà exister :

```bash
chiffremento -mode dec -in photos.chto
```

Contrôler qu'une sauvegarde est intacte et déchiffrable, sans rien écrire sur le disque :

```bash
chiffremento -mode verify -in sauvegarde.tar.gz.chto
```

Mesurer les coûts sur cette machine, pour choisir un profil en connaissance de cause :

```bash
chiffremento -mode bench
```

Renforcer la dérivation de clé :

```bash
chiffremento -mode enc -in secret.pdf -kdf fort
```

Conserver le nom et la date d'origine à l'intérieur du chiffré, pour pouvoir sortir sous un nom neutre :

```bash
chiffremento -mode enc -in rapport-medical.pdf -out a3f9c2.chto -meta minimal
```

Au déchiffrement, le nom n'est lisible qu'une fois le contenu authentifié : la ligne de commande l'affiche sans renommer d'autorité, l'interface guidée propose de rendre son nom au fichier.

Inspecter un fichier sans le déchiffrer ni saisir de mot de passe :

```bash
chiffremento -mode info -in document.txt.chto
```

Changer le mot de passe sans re-chiffrer le contenu — l'ancien est demandé, puis le nouveau :

```bash
chiffremento -mode passwd -in document.txt.chto
```

Mode parano avec compression :

```bash
chiffremento -mode enc -in backup.db -parano -comp
```

Écrire ailleurs que dans le dossier de la source :

```bash
chiffremento -mode enc -in photos -out /volumes/sauvegarde/photos.chto
```

Masquer la taille réelle du fichier :

```bash
chiffremento -mode enc -in contrat.pdf -pad
```

Trois largeurs de palier au choix. Ce qui compte n'est pas la taille du palier, mais le nombre de fichiers qui sortent à la **même** taille — mesuré sur des fichiers de 7,5 à 7,9 Mo :

| `-pad-niveau` | tailles distinctes obtenues | surcoût maximal |
|---|---|---|
| `standard` *(défaut)* | 7 605 925 · 7 737 061 · 7 999 333 | ~12 % |
| `fort` | 7 605 925 · 7 868 197 · 8 130 469 | ~25 % |
| `maximum` | 8 392 741 — **une seule** | ~100 % |

```bash
chiffremento -mode enc -in contrat.pdf -pad -pad-niveau maximum
```

Le palier reste proportionnel à la taille à tous les niveaux : un pas fixe — arrondir tout le monde au multiple de 10 Mo supérieur — gonflerait un fichier de 3 Ko d'un facteur mille et ne masquerait plus rien à 1,4 Go, où 10 Mo ne pèsent plus que 0,7 %. Ajouter de l'aléa au remplissage serait contre-productif pour la même raison inverse : un palier fixe met tout un intervalle sur une valeur unique, alors qu'un tirage disperse les tailles à l'intérieur du palier et redonne à un observateur de quoi séparer deux fichiers.

Lister une sauvegarde de dossier sans l'extraire, en passant le tar à `tar` :

```bash
chiffremento -mode dec -in photos.chto -out - | tar tf -
```

Depuis un script, le mot de passe se fournit sur l'entrée standard :

```bash
echo "$MOT_DE_PASSE" | chiffremento -mode enc -in backup.db
```

> Avec `-in -`, l'entrée standard porte les données : le mot de passe est alors demandé sur le terminal (`/dev/tty`). Sans terminal, l'outil refuse plutôt que de lire la première ligne des données comme mot de passe.

## 🗂️ Format de fichier

```
magic       8 o   "CHFRMT03"
version     1 o   1 à 3 (anciens), 4 (courant)
flags       1 o   bit 0 = compressé (v1/v2), bit 1 = archive tar, bit 2 = rempli,
                  bit 3 = métadonnées
algo        1 o   1 = AES-GCM, 2 = ChaCha20-Poly1305, 3 = cascade
argonTime   4 o   uint32 big-endian        ┐
argonMemory 4 o   uint32 big-endian (KiB)  ├ v2 et suivantes
argonPar    1 o   uint8                    ┘
compAlgo    1 o   0 = aucune, 1 = gzip (lu, plus écrit), 2 = zstd  ─ v3 et suivantes
salt       16 o
commit     32 o   engagement sur la clé maîtresse   ┐
wrappedDEK 48 o   clé du fichier, scellée           ┘ v4
```

**Dérivation en v4.** `masterKey = Argon2id(mot de passe, sel, paramètres)`, puis trois usages séparés par `HKDF-Expand`, chacun sous son étiquette :

| Sortie | Rôle |
| :--- | :--- |
| `commit` (32 o) | écrit dans l'en-tête, comparé en temps constant **avant** tout déchiffrement |
| `kek` + nonce (44 o) | ouvre l'enveloppe qui contient la clé du fichier |
| — | les clés du contenu, elles, viennent de la **DEK**, tirée au hasard par fichier |

Deux propriétés en découlent :

- **Engagement de clé.** AES-GCM et ChaCha20-Poly1305 ne sont pas engageants : on peut fabriquer un chiffré valide sous plusieurs clés, ce qu'exploitent les [attaques par oracle de partitionnement](https://www.usenix.org/conference/usenixsecurity21/presentation/len). Le tag `commit` ferme cette porte, et rend au passage un message clair — « mot de passe incorrect » — au lieu d'une erreur d'authentification survenue au milieu du fichier.
- **Changement de mot de passe instantané.** La clé du contenu ne dépend plus du mot de passe : `-mode passwd` réécrit les 117 octets d'en-tête, quelle que soit la taille du fichier.

L'en-tête reste authentifié : il sert de données associées (AAD) au scellement de l'enveloppe, donc en modifier un octet — version, algorithme, sel, engagement — empêche l'ouverture. C'est ce qui remplace, en v4, le liage par HKDF des versions 2 et 3.

Les fichiers en version 1, 2 et 3 sont relus avec leur dérivation d'origine. Les nouveaux fichiers sont toujours écrits en version 4.

La v3 remplace le drapeau de compression par un champ : un bit ne pouvait pas distinguer gzip de zstd, et empiler un bit par algorithme rendait possibles des états contradictoires. En v1 et v2, le bit 0 signifiait gzip — c'est le seul sens qu'il ait jamais eu, donc la relecture est directe. Un binaire plus ancien refuse un fichier v3 au lieu de l'interpréter de travers.

## 🔑 Profils de dérivation

Les paramètres Argon2 sont inscrits dans chaque fichier, donc ajustables sans casser l'existant.

| Profil | Mémoire | Passes | Coût mesuré |
| :--- | ---: | ---: | ---: |
| `standard` *(défaut)* | 256 Mio | 3 | ~140 ms |
| `fort` | 512 Mio | 4 | ~350 ms |
| `maximum` | 1 Gio | 4 | ~730 ms |

> **Le déchiffrement exige la même mémoire que le chiffrement.** Un fichier scellé en `maximum` sera indéchiffrable sur une machine qui n'a pas 1 Gio à consacrer à la dérivation. `chiffremento -mode bench` mesure les trois profils sur votre machine et conseille le plus robuste qui reste raisonnable, en tenant compte de cette contrainte.

## ⚠️ Modèle de menace

Ce que l'outil protège :

- le **contenu** d'un fichier au repos : disque volé, sauvegarde envoyée sur un service tiers, clé USB perdue ;
- l'**intégrité** : toute modification du contenu chiffré ou de l'en-tête est détectée, le déchiffrement échoue.

Ce que l'outil **ne** protège **pas** :

- le **nom du fichier** : `secret.pdf.chto` annonce son contenu ;
- la **taille** : elle suit celle du fichier d'origine, à quelques dizaines d'octets près ;
- les **métadonnées** : dates et permissions d'origine ne sont pas conservées ;
- sous **Windows**, les fichiers produits ne sont pas restreints en `0600` : le système n'a pas de bits de permission POSIX et l'accès y dépend des ACL, que cet outil ne touche pas. Sur macOS et Linux, la restriction est bien appliquée ;
- avec `-comp`, la **compressibilité** du contenu fuit à travers la taille finale ;
- une **machine compromise** : keylogger, mémoire lue par un autre processus, fichier d'origine encore présent sur le disque après chiffrement.

La solidité dépend **entièrement** de la force du mot de passe. Argon2id rend chaque tentative coûteuse (~150 ms), mais un mot de passe court reste cassable. Utilisez une phrase de passe longue.

Le mode parano ne remplace pas un bon mot de passe : il protège contre la découverte d'une faiblesse dans un seul des deux algorithmes, rien d'autre.

---
<br>

<a id="-english"></a>

# 🇬🇧 English

**Chiffremento CLI** is a command-line tool written in Go for encrypting and decrypting files. It offers a guided interface, or flags for scripting.

## ✨ New in v2.1

> The **file format** moved to v4 in this release. The two numbers are independent: the program version tracks its features, the format version tracks its binary layout. `chiffremento -mode info` shows a given file's format version.

- **📁 Folders**: encrypt a whole folder, packed into a tar stream as it is encrypted and recreated as-is on decryption.
- **🗜️ zstd**: replaces gzip, measured ~8× faster at a comparable ratio. gzip is no longer produced, only read back: compressed v1 and v2 `.chto` files stay decryptable. Compression is now described by a header field rather than a single bit.
- **📏 `-pad`**: masks the real size of the contents by rounding up to the next bucket.
- **🔗 `-out`, `-in -`, `-out -`**: choose the destination, and use the standard streams to compose with other tools.
- **🗂️ File browser** in the guided interface, as an alternative to typing the path.
- **📊 Dictionary-based password strength**: `azerty123` is finally reported as weak.
- **🔑 Derivation profiles**: `-kdf standard|fort|maximum`, from fastest to costliest to attack.
- **🏷️ `-meta minimal`**: keeps the original name and date inside the ciphertext, so output can use a neutral name.
- **📊 `-mode bench`**: measures the profiles and algorithm throughput on your machine, and advises a profile.

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
- **📁 Files and folders**: a folder is packed into a **tar** stream as it is encrypted — no intermediate archive on disk — and recreated as-is on decryption. Symlinks are rejected, and an archive can never write outside the destination folder.
- **📦 Compression**: **zstd**, optional before encryption and offered pre-enabled for folders. It replaces gzip, measured ~8× faster at a comparable ratio; existing gzip files stay decryptable but are no longer produced.
- **📏 Size masking**: the `-pad` option rounds the size up to the next bucket ([Padmé scheme](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf)), so a `.chto` no longer betrays the exact size of its contents.
- **🔗 Composable**: `-in -` and `-out -` read from and write to the standard streams.
- **📊 Realistic strength meter**: password strength is scored by [`zxcvbn`](https://github.com/trustelem/zxcvbn), which recognises dictionary words, names, dates and keyboard patterns. `azerty123` is reported at ~13 bits, not ~60.
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

It asks for the operation, then how to point at the target: **type a path** (or drag and drop it), or **browse files**. In the browser, `↑↓` move, `→` enters a folder and `enter` selects.

Every decision follows the same grammar: `↑↓` move through the answers, `→` (or `enter`) confirms, `←` goes back to the previous decision — across screens too, keeping the answers already given. In a text field and in the browser, where `←` already has a job, going back is `shift+tab`.

When encrypting, once the original name and date are kept inside the ciphertext, it offers to **scramble those of the file it writes**: a randomly drawn name — `3fb8db8ee5db3891.chto` — dated 1 January 2000. Decryption restores both. The *creation* date stays that of the actual write: no userspace call changes it, so the scrambling hides the date from an ordinary look, not from an inspection of the filesystem.

When size masking is on, it also asks for the **bucket width**, showing what each step costs on *this* file: "7.2 Mo → environ 8.0 Mo (+11.8 %) · tout ce qui pèse de 4.0 Mo à 8.0 Mo sort identique".

Once the operation is done, it finally offers to **delete what it replaces**: the original after encryption, the `.chto` after decryption. An original is only erased after the ciphertext has been read back and fully authenticated — the original is the only other copy. "Keep" is always the answer under the cursor, and deleting removes the directory entry without wiping the data from the medium.

### Command line

```bash
chiffremento -mode <enc|dec|verify|info|passwd> -in <file> [options]
```

The password is **never an argument**. It is prompted for with masked input, or read from standard input when that is not a terminal.

| Flag | Description |
| :--- | :--- |
| `-mode` | **Required.** `enc` (encrypt), `dec` (decrypt), `verify` (check without writing anything), `info` (inspect the header), `passwd` (change the password) or `bench` (measure costs). |
| `-in` | **Required.** Input file or folder, or `-` for standard input. |
| `-out` | Destination. Defaults to the input plus `.chto` for `enc`, the input without the extension for `dec`. `-` writes to standard output. |
| `-comp` | *(enc)* Enables zstd compression. |
| `-pad` | *(enc)* Masks the real size. Mutually exclusive with `-comp`. |
| `-pad-niveau` | *(enc)* Bucket width: `standard` (default), `fort` or `maximum`. Requires `-pad`. |
| `-chacha` | *(enc)* Uses ChaCha20-Poly1305 instead of AES-GCM. |
| `-parano` | *(enc)* Cascaded double encryption. Mutually exclusive with `-chacha`. |
| `-kdf` | *(enc)* Key derivation cost: `standard` (default), `fort` or `maximum`. |
| `-meta` | *(enc)* Metadata kept: `none` (default) or `minimal` (name and date). |
| `-force` | *(enc, dec)* Overwrites the destination if it already exists. Without it, the operation is refused. Never applies to an extracted folder. |
| `-version` | Prints the version. |

> An existing destination is **refused by default**: decrypting `doc.pdf.chto`
> next to an unrelated `doc.pdf` will not destroy it. Use `-force` to overwrite
> deliberately. An extracted folder is never overwritten, even with `-force`:
> that would mean deleting an entire tree.

### Examples

Encrypt (creates `document.txt.chto`):

```bash
chiffremento -mode enc -in document.txt
```

Decrypt (recreates `document.txt`):

```bash
chiffremento -mode dec -in document.txt.chto
```

Encrypt a folder (creates `photos.chto`, holding the whole tree):

```bash
chiffremento -mode enc -in photos
```

Decrypting it recreates the `photos` folder, which must not already exist:

```bash
chiffremento -mode dec -in photos.chto
```

Check that a backup is intact and decryptable, without writing anything to disk:

```bash
chiffremento -mode verify -in backup.tar.gz.chto
```

Measure costs on this machine, to pick a profile knowingly:

```bash
chiffremento -mode bench
```

Strengthen key derivation:

```bash
chiffremento -mode enc -in secret.pdf -kdf fort
```

Keep the original name and date inside the ciphertext, so you can output under a neutral name:

```bash
chiffremento -mode enc -in medical-report.pdf -out a3f9c2.chto -meta minimal
```

On decryption the name is only readable once the content is authenticated: the command line prints it without renaming anything, while the guided interface offers to give the file its name back.

Inspect a file without decrypting it or entering a password:

```bash
chiffremento -mode info -in document.txt.chto
```

Change the password without re-encrypting the contents — the old one is asked for, then the new one:

```bash
chiffremento -mode passwd -in document.txt.chto
```

Parano mode with compression:

```bash
chiffremento -mode enc -in backup.db -parano -comp
```

Write somewhere other than next to the source:

```bash
chiffremento -mode enc -in photos -out /volumes/backup/photos.chto
```

Mask the real file size:

```bash
chiffremento -mode enc -in contract.pdf -pad
```

Three bucket widths. What matters is not the bucket size but how many files come out at the **same** size — measured on files from 7.5 to 7.9 MB:

| `-pad-niveau` | distinct sizes produced | maximum overhead |
|---|---|---|
| `standard` *(default)* | 7,605,925 · 7,737,061 · 7,999,333 | ~12 % |
| `fort` | 7,605,925 · 7,868,197 · 8,130,469 | ~25 % |
| `maximum` | 8,392,741 — **a single one** | ~100 % |

```bash
chiffremento -mode enc -in contract.pdf -pad -pad-niveau maximum
```

The bucket stays proportional to the size at every level: a fixed step — rounding everything up to the next 10 MB — would inflate a 3 KB file a thousandfold and mask nothing at 1.4 GB, where 10 MB is only 0.7 %. Adding randomness to the padding would be counter-productive for the mirror reason: a fixed bucket collapses a whole interval onto one value, whereas a random draw spreads sizes inside the bucket and hands an observer a way to tell two files apart again.

List a folder backup without extracting it, by piping the tar into `tar`:

```bash
chiffremento -mode dec -in photos.chto -out - | tar tf -
```

From a script, supply the password on standard input:

```bash
echo "$PASSWORD" | chiffremento -mode enc -in backup.db
```

> With `-in -`, standard input carries the data, so the password is asked for on the terminal (`/dev/tty`). With no terminal available, the tool refuses rather than reading the first line of your data as the password.

## 🗂️ File format

```
magic       8 B   "CHFRMT03"
version     1 B   1 to 3 (legacy), 4 (current)
flags       1 B   bit 0 = compressed (v1/v2), bit 1 = tar archive, bit 2 = padded,
                  bit 3 = metadata
algo        1 B   1 = AES-GCM, 2 = ChaCha20-Poly1305, 3 = cascade
argonTime   4 B   uint32 big-endian        ┐
argonMemory 4 B   uint32 big-endian (KiB)  ├ v2 onwards
argonPar    1 B   uint8                    ┘
compAlgo    1 B   0 = none, 1 = gzip (read-only), 2 = zstd  ─ v3 onwards
salt       16 B
commit     32 B   commitment to the master key   ┐
wrappedDEK 48 B   file key, sealed               ┘ v4
```

**v4 derivation.** `masterKey = Argon2id(password, salt, params)`, then three separate uses via `HKDF-Expand`, each under its own label:

| Output | Role |
| :--- | :--- |
| `commit` (32 B) | written in the header, compared in constant time **before** any decryption |
| `kek` + nonce (44 B) | opens the envelope holding the file key |
| — | the content keys come from the **DEK**, drawn at random per file |

Two properties follow:

- **Key commitment.** AES-GCM and ChaCha20-Poly1305 are not committing: one can craft a ciphertext valid under several keys, which is what [partitioning oracle attacks](https://www.usenix.org/conference/usenixsecurity21/presentation/len) exploit. The `commit` tag closes that door, and incidentally returns a clear message — "wrong password" — instead of an authentication error hit midway through the file.
- **Instant password change.** The content key no longer depends on the password: `-mode passwd` rewrites the 117-byte header, whatever the file size.

The header stays authenticated: it is the associated data (AAD) of the envelope seal, so changing one byte — version, algorithm, salt, commitment — prevents it from opening. That replaces, in v4, the HKDF binding used by versions 2 and 3.

Version 1, 2 and 3 files are read back with their original derivation. New files are always written as version 4.

## 🔑 Derivation profiles

Argon2 parameters are written into every file, so they can be raised without breaking existing ones.

| Profile | Memory | Passes | Measured cost |
| :--- | ---: | ---: | ---: |
| `standard` *(default)* | 256 MiB | 3 | ~140 ms |
| `fort` | 512 MiB | 4 | ~350 ms |
| `maximum` | 1 GiB | 4 | ~730 ms |

> **Decryption requires the same memory as encryption.** A file sealed with `maximum` will be undecryptable on a machine that cannot spare 1 GiB for derivation. `chiffremento -mode bench` measures all three on your machine and advises the strongest that stays reasonable, taking that constraint into account.

## ⚠️ Threat model

What this tool protects:

- the **contents** of a file at rest: stolen disk, backup uploaded to a third party, lost USB drive;
- **integrity**: any modification of the ciphertext or the header is detected and decryption fails.

What it does **not** protect:

- the **filename**: `secret.pdf.chto` advertises its own contents;
- the **size**: it tracks the original file's size within a few dozen bytes;
- **metadata**: original timestamps and permissions are not preserved;
- on **Windows**, output files are not restricted to `0600`: the system has no POSIX permission bits and access is governed by ACLs, which this tool does not touch. On macOS and Linux the restriction is applied;
- with `-comp`, the content's **compressibility** leaks through the final size;
- a **compromised machine**: keyloggers, memory read by another process, or the original file still sitting on disk after encryption.

Security depends **entirely** on password strength. Argon2id makes each attempt expensive (~150 ms), but a short password is still crackable. Use a long passphrase.

Parano mode is not a substitute for a good password: it guards against a weakness being found in one of the two algorithms, nothing more.

## 📄 License

MIT — see [LICENSE](LICENSE).

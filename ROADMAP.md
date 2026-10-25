# Roadmap Chiffremento CLI

> **Légende**
> - 🔥 **Priorité haute** · ⭐️ **Priorité moyenne** · ☁️ **Idées futures**
> - 🟢 **Facile** | 🟡 **Moyen** | 🔴 **Difficile**

Dernière version publiée : **v2.4.0**. Le format de fichier en est à la **v4**.

---

## ✅ Livré

### v2.0 — l'outil devient utilisable à la main

Interface guidée (`huh` + `bubbletea`) lancée sans argument, barre de progression, écriture atomique, format v2 (paramètres Argon2 dans le fichier, en-tête lié à la clé), Argon2id à 256 Mio, mode cascade corrigé (une seule dérivation), suppression du flag `-key`, `-mode info`, `-mode verify`, nettoyage des temporaires sur Ctrl+C.

### v2.1 — format v3, dossiers et réglages

- **Dossiers** chiffrés en une archive tar, extraite au déchiffrement
- **Format v3** : identifiant de compression explicite, zstd à la place de gzip (gzip reste relu)
- **Masquage de taille** (`-pad`) par le schéma [Padmé](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf)
- **Profils KDF** (`-kdf standard|fort|maximum`) : 256 Mio / 512 Mio / 1 Gio, sous le plafond de lecture de 2 Gio
- **Métadonnées optionnelles** (`-meta minimal`) : nom d'origine et date, à l'intérieur du chiffré, date arrondie à l'heure
- **`-mode bench`** : Argon2id et débit AEAD mesurés sur la machine, pour choisir un profil en connaissance de cause
- **Tubes** : `-in -` et `-out -`
- **Force du mot de passe** par zxcvbn, qui reconnaît les motifs de clavier et les mots du dictionnaire
- **Refus d'écraser** une destination existante sans `-force`

### v2.2.1 — correctifs

Flèche droite qui ne validait pas la dernière question d'un écran (explorateur inatteignable), perte de fichier possible au changement de mot de passe sur un disque qui décroche, deux défauts Windows (sauvegarde d'en-tête tronquée, nom d'origine refusé par le système), palier de remplissage annoncé mais non produit au-delà du plafond, et quatre écarts de documentation dont le mécanisme d'authentification de l'en-tête v4.

### v2.2 — format v4, marche arrière et suppression après coup

- **Retour arrière dans l'interface guidée** : `↑↓` pour choisir, `→` pour valider, `←` pour revenir — d'un écran à l'autre, en gardant les réponses
- **Restitution du nom d'origine** au déchiffrement : il était stocké mais jamais ressorti
- **Brouillage du nom et de la date** du fichier chiffré, quand les métadonnées sont conservées
- **Suppression après coup** de l'original ou du chiffré, l'original seulement après relecture complète du chiffré
- **Largeur du palier de remplissage** (`-pad-niveau standard|fort|maximum`) : de « quelques pour cent » à « toute une octave sort à la même taille »
- **Format v4 : engagement de clé** — un tag de 32 octets comparé avant tout déchiffrement. Ferme la porte aux attaques par oracle de partitionnement, et rend un « mot de passe incorrect » lisible au lieu d'une erreur d'authentification
- **Format v4 : enveloppe DEK/KEK** — la clé du contenu est tirée au hasard et scellée dans l'en-tête, donc indépendante du mot de passe
- **`-mode passwd`** — changer le mot de passe en réécrivant 117 octets, quelle que soit la taille du fichier ; disponible aussi dans l'interface guidée

### v2.3 — phrase de passe générée, et un outil plus léger

- **Phrase de passe générée** à l'étape du mot de passe : 7 mots français tirés de `crypto/rand`, environ 128 bits, masquée, copiable, avec confirmation avant de chiffrer. En ligne de commande : `-mode genpass [-mots N]`
- **Mémoire d'Argon2 rendue au système** dès la clé dérivée : 272 → 17 Mo pendant le traitement d'un gros fichier, 528 → 272 Mo pour `-mode passwd`
- **Extraction d'un dossier synchronisée sur disque**, en 0,55 s pour 5 000 fichiers sous macOS, et tolérante aux volumes sans synchronisation (exFAT, SMB, NFS)
- **Fiabilité** : Ctrl+C, source modifiée jamais effacée, écriture atomique depuis un flux, `install.sh` vérifié par `checksums.txt`

### v2.4 — interface plein écran, force du mot de passe en français, releases signées

- **Interface plein écran** : un seul écran, menu qui revient après chaque opération, `Échap` / `q` / `?` / `o`, carte résultat, écran d'erreur avec conseil
- **Phrase gardée pour la session**, sur demande : oubliée après 5 minutes, par `o` ou à la sortie
- **zxcvbn interne et allégé** : mots, prénoms et noms français (INSEE), accents compris ; binaire 8 348 898 → 6 312 914 o ; `-version` ~15,5 → ~4,2 Mo de pic mémoire ; défauts de la version d'origine corrigés (mot de passe estimé à 0 essai, `andré`)
- **Releases signées** : signature cosign de `checksums.txt`, SBOM par archive, attestation de provenance ; `install.sh` vérifie la signature
- **Fiabilité** : plus aucun temporaire déchiffré après Ctrl+C, fermeture de la fenêtre ou plantage ; copie du mot de passe effacée avant la sortie ; course de données corrigée entre la saisie du mot de passe et sa confirmation
- Le format de fichier ne change pas (v4)

---

## Ce qui reste

### ⭐️ Confort

- **🟢 Fichier-clé en second facteur** — combiner le mot de passe et le contenu d'un fichier (clé USB) par HKDF : `-keyfile /Volumes/USB/cle.bin`. Le mot de passe seul ne suffit plus.
- **🟢 Sortie ASCII (`-armor`)** — base64 avec en-tête et pied lisibles, pour coller un secret dans un mail. Ce que fait `age --armor`.
- **🟢 Complétions shell et page de manuel** — bash, zsh, fish.
- **🟡 Métadonnées : ce qui manque** — les permissions ne sont pas conservées, et il n'existe que deux niveaux (`none`, `minimal`). Un niveau intermédiaire n'a d'intérêt que si quelqu'un le demande.

### ⭐️ 🔴 Mode destinataire et post-quantique

> Le mode mot de passe actuel est **déjà résistant au quantique** : Argon2id et AES-256/ChaCha20 sont symétriques, Grover ramène 256 bits à 128, hors d'atteinte. Le post-quantique ne devient un sujet qu'avec un mode à **clé publique**, où X25519 et RSA tomberaient face à Shor.

- `chiffremento -mode keygen` : une paire de clés, pour chiffrer à quelqu'un sans mot de passe partagé, comme `age`.
- Encapsulation **hybride X25519 + ML-KEM-768**, les deux secrets combinés par HKDF (jamais par XOR, jamais ML-KEM seul : le post-quantique est jeune, l'hybride garde la sécurité classique si la cryptanalyse progresse).
- **Zéro dépendance** : `crypto/mlkem` (FIPS 203) et `crypto/ecdh` sont dans la bibliothèque standard, le projet est en Go 1.26. Surveiller `crypto/hpke` si un KEM hybride y arrive.
- Impact format : un identifiant d'algorithme et un bloc « destinataire » dans l'en-tête — l'encapsulation ML-KEM-768 pèse 1 088 octets.
- **Prérequis levé** : l'enveloppe DEK/KEK est en place depuis la v4 du format. Il reste à porter plusieurs enveloppes par fichier — aujourd'hui il n'y en a qu'une, et rien dans l'en-tête ne prévoit d'en compter.

---

## Écarté, et pourquoi

Gardé ici pour ne pas re-proposer ces pistes tous les six mois.

- **Un quatrième algorithme de chiffrement.** `minio/sio` ne connaît qu'AES-GCM et ChaCha20-Poly1305 : en ajouter un veut dire abandonner le format DARE et écrire soi-même le découpage en blocs authentifiés — c'est là que se logent les bugs de troncature et de réordonnancement que DARE empêche gratuitement. Ce n'est pas un ajout d'algorithme, c'est une réécriture du cœur. **AEGIS-256** serait le candidat naturel le jour où le format serait réécrit pour une autre raison ; **XChaCha20-Poly1305** et **AES-GCM-SIV** résolvent des problèmes de nonce que DARE n'a pas.
- **Chunking parallèle.** Mesuré : le temps est dominé par Argon2, pas par le chiffrement. Paralléliser les blocs déplacerait le risque (nonce et index par bloc) sans déplacer l'attente.
- **Remplissage à pas fixe** (arrondir tout le monde au multiple de 10 Mo supérieur). Le pas doit être proportionnel à la taille : un pas fixe gonfle un fichier de 3 Ko d'un facteur mille et ne masque plus rien à 1,4 Go, où 10 Mo pèsent 0,7 %.
- **Remplissage aléatoire** par-dessus le palier. Un palier déterministe met tout un intervalle sur une taille unique — c'est ce qui protège. Un tirage disperse les tailles à l'intérieur du palier, redonne de quoi séparer deux fichiers, et sur plusieurs chiffrements du même fichier la moyenne converge vers la taille réelle. La rondeur n'a rien à cacher : le drapeau de remplissage est déjà lisible en clair dans l'en-tête.
- **Effacement sécurisé** (réécriture avant suppression). Sur SSD, le contrôleur décide seul de ce qu'il réécrit : aucune promesse tenable depuis l'espace utilisateur. La suppression proposée par l'interface dit ce qu'elle fait — elle retire l'entrée, pas les données.

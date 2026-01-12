# Chiffremento CLI

Chiffremento CLI est une application en ligne de commande écrite en Go qui permet de chiffrer et déchiffrer des fichiers de manière sécurisée. Elle supporte plusieurs algorithmes de chiffrement (AES-GCM, ChaCha20-Poly1305) ainsi que la compression des données.

## Fonctionnalités

- **Chiffrement Authentifié** : Utilise AES-GCM (par défaut) ou ChaCha20-Poly1305.
- **Dérivation de Clé Robuste** : Utilise Argon2id pour dériver la clé de chiffrement à partir du mot de passe.
- **Compression** : Support optionnel de la compression GZIP avant chiffrement.
- **Mode Parano** : Un mode "Cascade" qui double-chiffre les données (AES puis ChaCha20) pour une sécurité maximale.
- **Format de Fichier Sécurisé** : En-tête personnalisé incluant Magic Number, version, flags, et sel aléatoire.

## Installation

Assurez-vous d'avoir Go installé (version 1.25+ recommandée).

```bash
# Clonez le dépôt (si applicable)
cd chiffremento-go-cli
# Compilez le projet
go build -o chiffremento main.go
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

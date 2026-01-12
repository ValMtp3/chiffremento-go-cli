# Chiffremento CLI

Chiffremento CLI est une application en ligne de commande écrite en Go qui permet de chiffrer et déchiffrer des fichiers en utilisant l'algorithme AES-GCM avec une dérivation de clé via Argon2. Ce projet est conçu pour offrir un chiffrement sécurisé et authentifié pour protéger des fichiers sensibles.

## Fonctionnement général

L'application fonctionne en deux modes principaux :
- **Chiffrement (enc)** : Prend un fichier en entrée, le chiffre avec un mot de passe fourni, et écrit le résultat dans un fichier de sortie.
- **Déchiffrement (dec)** : Prend un fichier chiffré en entrée, le déchiffre avec le même mot de passe, et écrit le contenu déchiffré dans un fichier de sortie.

Le chiffrement utilise :
- **AES-GCM** pour le chiffrement authentifié (garantit l'intégrité et la confidentialité).
- **Argon2** pour la dérivation de clé à partir du mot de passe (résiste aux attaques par brute force).
- Un sel aléatoire et un nonce pour chaque opération de chiffrement.

Le format du fichier chiffré est : `[sel 16 octets][nonce 12 octets][texte chiffré]`.

## Structure du projet

```
chiffremento_cli_go/
├── main.go              # Point d'entrée de l'application CLI
├── pkg/
│   ├── crypto.go        # Logique de chiffrement et déchiffrement
│   └── crypto_test.go   # Tests unitaires
├── go.mod               # Dépendances du module Go
├── go.sum               # Sommes de contrôle des dépendances
└── README.md            # Ce fichier
```

## Explication détaillée du code

### main.go

Le fichier `main.go` définit l'interface en ligne de commande à l'aide du package `flag` de Go. Il gère les arguments suivants :
- `-mode` : Mode d'opération ("enc" pour chiffrer, "dec" pour déchiffrer)
- `-in` : Chemin du fichier d'entrée
- `-out` : Chemin du fichier de sortie
- `-key` : Mot de passe pour le chiffrement/déchiffrement

Le programme valide que tous les paramètres sont fournis, puis appelle les fonctions appropriées du package `pkg` selon le mode choisi.

### pkg/crypto.go

Ce fichier contient la logique métier du chiffrement et déchiffrement.

#### Constantes

- `argonTime`, `argonMemory`, `argonThreads`, `argonKeyLen` : Paramètres pour Argon2 (dérivation de clé).
- `saltSize` (16 octets), `nonceSize` (12 octets) : Tailles pour le sel et le nonce.
- `magicNumber`, `versionSize`, etc. : Définitions pour un format de fichier étendu (non encore implémenté dans les fonctions actuelles).
- `currentVersion`, `FlagCompressed`, etc. : Pour une future extension du format.

#### Fonction deriveKey

```go
func deriveKey(password []byte, salt []byte) ([]byte, error)
```

- Si aucun sel n'est fourni (longueur 0), génère un nouveau sel aléatoire de 16 octets.
- Utilise Argon2 pour dériver une clé de 32 octets à partir du mot de passe et du sel.
- **Note** : La fonction retourne seulement la clé, pas le sel généré, ce qui peut poser des problèmes de cohérence (comme noté dans l'analyse existante).

#### Fonction Encrypt

```go
func Encrypt(inputPath string, outputPath string, password []byte) error
```

Étapes :
1. Lit le fichier d'entrée en entier en mémoire.
2. Génère un sel aléatoire de 16 octets.
3. Dérive la clé à partir du mot de passe et du sel.
4. Crée un cipher AES avec la clé.
5. Initialise GCM (Galois/Counter Mode) pour le chiffrement authentifié.
6. Génère un nonce aléatoire de 12 octets.
7. Chiffre les données avec GCM.
8. Écrit dans le fichier de sortie : sel + nonce + texte chiffré.
9. Retourne une erreur si une étape échoue.

#### Fonction Decrypt

```go
func Decrypt(inputPath string, outputPath string, password []byte) error
```

Étapes :
1. Lit le fichier chiffré en entier en mémoire.
2. Vérifie que le fichier fait au moins 28 octets (sel + nonce).
3. Extrait le sel (premiers 16 octets), le nonce (16-28), et le texte chiffré (reste).
4. Dérive la clé à partir du mot de passe et du sel extrait.
5. Crée un cipher AES et GCM.
6. Déchiffre et vérifie l'authenticité avec GCM.
7. Écrit le texte déchiffré dans le fichier de sortie.
8. Retourne une erreur si le déchiffrement échoue (mauvais mot de passe, fichier corrompu, etc.).

### pkg/crypto_test.go

Contient des tests unitaires pour valider le fonctionnement :
- `TestEncryptDecrypt` : Teste un cycle complet chiffrement/déchiffrement avec vérification de l'intégrité.
- `TestDecryptWithWrongPassword` : Vérifie que le déchiffrement échoue avec un mauvais mot de passe.
- `TestDecryptInvalidFile` : Vérifie la gestion des fichiers invalides (trop courts).

## Utilisation

### Compilation

Assurez-vous d'avoir Go installé (version 1.25.4 ou supérieure).

```bash
cd chiffremento_cli_go
go build -o chiffremento main.go
```

### Exemples d'utilisation

#### Chiffrement d'un fichier

```bash
./chiffremento -mode enc -in fichier_clair.txt -out fichier_chiffre.bin -key "monmotdepasse"
```

#### Déchiffrement d'un fichier

```bash
./chiffremento -mode dec -in fichier_chiffre.bin -out fichier_dechiffre.txt -key "monmotdepasse"
```

### Sécurité

- Utilisez un mot de passe fort (au moins 8 caractères, mélange de lettres, chiffres, symboles).
- Le mot de passe est passé en argument, ce qui peut être visible dans l'historique du shell. Pour une meilleure sécurité, considérez une modification pour lire le mot de passe via stdin.
- Les fichiers sont lus en entier en mémoire ; pour de gros fichiers, une implémentation en streaming serait nécessaire.

## Tests

Pour exécuter les tests :

```bash
go test ./pkg
```

Les tests vérifient les fonctionnalités de base et la robustesse contre les erreurs courantes.

## Limitations et améliorations possibles

- Le format de fichier actuel est basique ; l'implémentation complète avec en-tête (magic number, version, flags) n'est pas utilisée.
- Pas de gestion des gros fichiers (tout est en mémoire).
- Pas de validation avancée des paramètres dans main.go.
- Messages d'erreur en français dans main.go, mais code en anglais.
- Pas de mode interactif ou d'options avancées.

Pour des améliorations détaillées, consultez l'analyse existante dans ce dépôt.
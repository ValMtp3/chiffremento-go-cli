#!/bin/bash

set -e

BINARY_NAME="chiffremento"
# CHIFFREMENTO_INSTALL_DIR : dossier d'installation, /usr/local/bin par défaut.
# Sert surtout aux tests, pour ne rien écrire dans le système.
INSTALL_DIR="${CHIFFREMENTO_INSTALL_DIR:-/usr/local/bin}"

# Identité attendue de la signature : le workflow release.yml de ce dépôt, sur
# un tag v*. Ces deux valeurs sont les mêmes dans release.yml et RELEASE.md.
SIGNATURE_IDENTITE='^https://github.com/ValMtp3/chiffremento-go-cli/.github/workflows/release.yml@refs/tags/v'
SIGNATURE_EMETTEUR='https://token.actions.githubusercontent.com'
WORKDIR=""

cleanup() { [ -n "$WORKDIR" ] && rm -rf "$WORKDIR"; }
trap cleanup EXIT

# 1. Détection du système et de l'architecture
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "$OS_RAW" in
    Darwin) OS="darwin" ;;
    Linux)  OS="linux" ;;
    *)
        echo "❌ Système non supporté automatiquement par ce script : $OS_RAW"
        exit 1
        ;;
esac

case "$ARCH_RAW" in
    x86_64|amd64)   ARCH="amd64" ;;
    arm64|aarch64)  ARCH="arm64" ;;
    *)
        echo "❌ Architecture non supportée : $ARCH_RAW"
        exit 1
        ;;
esac

echo "🔍 Détection du système : $OS/$ARCH"

# 2. Outil de somme de contrôle
if command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum"
else
    echo "❌ Ni shasum ni sha256sum disponibles : impossible de vérifier l'intégrité."
    exit 1
fi

CHECKSUMS=""
for candidate in "./checksums.txt" "./build/checksums.txt"; do
    [ -f "$candidate" ] && CHECKSUMS="$candidate" && break
done

# Signature de checksums.txt (cosign, sans clé). Elle passe AVANT toute
# lecture des empreintes : un checksums.txt falsifié rendrait la vérification
# SHA-256 inutile. Une vérification qui échoue (signature fausse ou réseau
# absent) refuse l'installation : jamais de repli silencieux.
verify_signature() {
    local bundle
    [ -z "$CHECKSUMS" ] && return 0

    if ! command -v cosign >/dev/null 2>&1; then
        echo "⚠️  signature non vérifiée : installe cosign pour plus de sûreté"
        return 0
    fi

    bundle="$(dirname "$CHECKSUMS")/checksums.txt.sigstore.json"
    if [ ! -f "$bundle" ]; then
        # Refus quelle que soit la version : sans signature, checksums.txt ne
        # prouve rien, et le nom de l'archive (donc sa « version ») est
        # modifiable par un attaquant.
        echo "❌ checksums.txt.sigstore.json est absent : installation refusée."
        echo "   Sans la signature, rien ne prouve que checksums.txt est authentique."
        echo "   Télécharge checksums.txt.sigstore.json depuis la même page de release, dans ce dossier, puis relance."
        echo "   Pour une release antérieure à la 2.4.0 (non signée), utilise l'install.sh fourni avec cette release."
        exit 1
    fi

    if ! cosign verify-blob --bundle "$bundle" \
        --certificate-identity-regexp "$SIGNATURE_IDENTITE" \
        --certificate-oidc-issuer "$SIGNATURE_EMETTEUR" \
        "$CHECKSUMS"; then
        echo "❌ Signature de checksums.txt non vérifiée : installation refusée."
        echo "   Soit la signature est fausse, soit cosign n'a pas pu la vérifier (réseau absent ?)."
        echo "   Rien n'est installé. Vérifie la connexion, retélécharge les fichiers, puis relance."
        exit 1
    fi
    echo "🔏 Signature vérifiée : checksums.txt"
}


# verify_checksum <fichier> — échoue si l'empreinte ne correspond pas.
# Renvoie 2 si le fichier n'est pas listé dans checksums.txt.
verify_checksum() {
    local file="$1"
    local name expected actual
    name="$(basename "$file")"

    [ -z "$CHECKSUMS" ] && return 2

    # Le format GNU préfixe parfois le nom d'une étoile en mode binaire.
    expected="$(awk -v f="$name" '$2 == f || $2 == "*"f {print $1}' "$CHECKSUMS" | head -n1)"
    [ -z "$expected" ] && return 2

    actual="$($SHA_CMD "$file" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "❌ Empreinte invalide pour $name — fichier modifié ou téléchargement corrompu."
        echo "   attendue : $expected"
        echo "   obtenue  : $actual"
        exit 1
    fi
    echo "🔒 Empreinte vérifiée : $name"
    return 0
}

# 3. Recherche de la source, par ordre de préférence
#
# a) l'archive publiée par les releases GitHub (chiffremento_<version>_<os>_<arch>.tar.gz),
#    c'est elle qui figure dans checksums.txt ;
# b) à défaut, un binaire nu produit par `make build-all`.
PATH_TO_BIN=""
ARCHIVE=""

for candidate in ./${BINARY_NAME}_*_${OS}_${ARCH}.tar.gz ./build/${BINARY_NAME}_*_${OS}_${ARCH}.tar.gz; do
    [ -f "$candidate" ] && ARCHIVE="$candidate" && break
done

# La signature passe avant toute lecture des empreintes (verify_checksum).
verify_signature

if [ -n "$ARCHIVE" ]; then
    echo "📦 Archive trouvée : $ARCHIVE"
    # Une archive non vérifiable n'est jamais installée : ce script finit par
    # un sudo cp, et une installation « non vérifiée » ne vaut pas mieux
    # qu'aucune vérification. (Une empreinte fausse sort déjà en erreur dans
    # verify_checksum ; ici, c'est l'absence d'empreinte qui est refusée.)
    verify_checksum "$ARCHIVE" || {
        echo "❌ $(basename "$ARCHIVE") n'est pas listé dans checksums.txt : installation refusée."
        echo "   Télécharge checksums.txt depuis la même release, dans ce dossier, puis relance."
        exit 1
    }
    WORKDIR="$(mktemp -d)"
    tar -xzf "$ARCHIVE" -C "$WORKDIR"
    PATH_TO_BIN="$WORKDIR/$BINARY_NAME"
    if [ ! -f "$PATH_TO_BIN" ]; then
        echo "❌ L'archive ne contient pas de binaire '$BINARY_NAME'."
        exit 1
    fi
else
    for candidate in "./$BINARY_NAME-$OS-$ARCH" "./build/$BINARY_NAME-$OS-$ARCH"; do
        [ -f "$candidate" ] && PATH_TO_BIN="$candidate" && break
    done

    if [ -z "$PATH_TO_BIN" ]; then
        echo "❌ Erreur : aucun binaire trouvé pour $OS/$ARCH dans ce dossier."
        echo "   Attendu, au choix :"
        echo "     • l'archive ${BINARY_NAME}_<version>_${OS}_${ARCH}.tar.gz de la page Releases"
        echo "     • ou le binaire $BINARY_NAME-$OS-$ARCH produit par 'make build-all'"
        exit 1
    fi

    echo "✅ Binaire trouvé : $PATH_TO_BIN"
    verify_checksum "$PATH_TO_BIN" || {
        echo "⚠️  Aucune empreinte disponible pour $(basename "$PATH_TO_BIN") : installation non vérifiée."
    }
fi

# 4. Installation dans $INSTALL_DIR (/usr/local/bin, ou CHIFFREMENTO_INSTALL_DIR)
echo "🚀 Installation de $BINARY_NAME dans $INSTALL_DIR..."
echo "🔑 Un mot de passe peut être demandé pour les permissions (sudo)..."

chmod +x "$PATH_TO_BIN"
sudo cp "$PATH_TO_BIN" "$INSTALL_DIR/$BINARY_NAME"

# 5. Nettoyage spécifique macOS (Gatekeeper)
if [ "$OS" = "darwin" ]; then
    echo "🍎 Tentative de suppression de la quarantaine macOS..."
    sudo xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
fi

echo ""
echo "🎉 Installation terminée !"
echo ""
echo "   chiffremento            interface guidée"
echo "   chiffremento -h         aide en ligne de commande"
echo ""

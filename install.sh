#!/bin/bash

set -e

BINARY_NAME="chiffremento"
INSTALL_DIR="/usr/local/bin"
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

if [ -n "$ARCHIVE" ]; then
    echo "📦 Archive trouvée : $ARCHIVE"
    verify_checksum "$ARCHIVE" || {
        echo "⚠️  $(basename "$ARCHIVE") n'est pas listé dans checksums.txt : installation non vérifiée."
        echo "   Télécharge checksums.txt depuis la même release pour activer la vérification."
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

# 4. Installation dans /usr/local/bin
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

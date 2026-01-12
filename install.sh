#!/bin/bash

set -e

BINARY_NAME="chiffremento"
INSTALL_DIR="/usr/local/bin"

# 1. Détection du système et de l'architecture
OS="$(uname -s)"
ARCH="$(uname -m)"
SOURCE_BIN=""

echo "🔍 Détection du système : $OS ($ARCH)"

case "$OS" in
    Darwin)
        if [ "$ARCH" = "arm64" ]; then
            SOURCE_BIN="chiffremento-darwin-arm64"
        else
            SOURCE_BIN="chiffremento-darwin-amd64"
        fi
        ;;
    Linux)
        if [ "$ARCH" = "x86_64" ]; then
            SOURCE_BIN="chiffremento-linux-amd64"
        elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
            SOURCE_BIN="chiffremento-linux-arm64"
        fi
        ;;
    *)
        echo "❌ Système non supporté automatiquement par ce script : $OS"
        exit 1
        ;;
esac

# 2. Recherche du binaire source (local ou build/)
PATH_TO_BIN=""

if [ -f "./$SOURCE_BIN" ]; then
    PATH_TO_BIN="./$SOURCE_BIN"
elif [ -f "./build/$SOURCE_BIN" ]; then
    PATH_TO_BIN="./build/$SOURCE_BIN"
else
    echo "❌ Erreur : Impossible de trouver le fichier '$SOURCE_BIN' dans ce dossier."
    echo "   Assurez-vous d'avoir téléchargé le fichier correspondant à votre système"
    echo "   et de lancer ce script dans le même dossier."
    exit 1
fi

echo "✅ Binaire trouvé : $PATH_TO_BIN"

# 3. Installation dans /usr/local/bin
echo "🚀 Installation de $BINARY_NAME dans $INSTALL_DIR..."
echo "🔑 Un mot de passe peut être demandé pour les permissions (sudo)..."

chmod +x "$PATH_TO_BIN"

sudo cp "$PATH_TO_BIN" "$INSTALL_DIR/$BINARY_NAME"

# 4. Nettoyage spécifique macOS (Gatekeeper)
if [ "$OS" = "Darwin" ]; then
    echo "🍎 Tentative de suppression de la quarantaine macOS..."
    sudo xattr -d com.apple.quarantine "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || true
fi

echo ""
echo "🎉 Installation terminée avec succès !"
echo "Vous pouvez maintenant utiliser la commande depuis n'importe où :"
echo ""
echo "   chiffremento -help"
echo ""

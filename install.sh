#!/bin/bash
set -e
REPO="peligro/proyecto_ia_1"
LATEST=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case $ARCH in x86_64) ARCH="x86_64";; aarch64|arm64) ARCH="arm64";; *) echo "Arquitectura no soportada: $ARCH"; exit 1;; esac
case $OS in linux|darwin) ;; *) echo "SO no soportado: $OS"; exit 1;; esac
FILE="ai-audit_${OS^}_$ARCH.tar.gz"
URL="https://github.com/$REPO/releases/download/$LATEST/$FILE"
echo "📦 Descargando $FILE..."
curl -L -o "$FILE" "$URL"
echo "🔍 Extrayendo..."
tar xzf "$FILE"
rm "$FILE"
echo "✅ ai-audit instalado en ./ai-audit"
echo "🚀 Ejecutar: ./ai-audit --help"

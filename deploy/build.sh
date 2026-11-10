#!/usr/bin/env bash
# Hyperwave: compila hub, sensore e interfaccia web. Si esegue come utente normale.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"

cd "$ROOT/core"
if ! command -v go >/dev/null && [[ -x bin/hw-hub && -x bin/hw-sensor ]]; then
  # archivio "completo" di un rilascio: i binari sono già compilati, sul server basta Node
  echo "==> core: Go non installato, uso i binari già presenti ($(bin/hw-hub version 2>/dev/null || echo "versione sconosciuta"))"
else
  echo "==> core (Go) $VERSION"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X hyperwave/internal/version.Version=$VERSION" -o bin/ ./cmd/...
  go test ./...
fi

echo "==> web (Next.js)"
cd "$ROOT/web"
if [[ -f package-lock.json ]]; then
  npm ci --no-audit --no-fund
else
  npm install --no-audit --no-fund
fi
npm run build

echo "Compilazione completata: core/bin/ e web/.next/"

#!/usr/bin/env bash
# Baut Oberfläche und Linux-Programm nach panel/dist/vpnpanel-linux-amd64
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
(cd web && npm ci && npm run build)
go test ./...
mkdir -p dist
GOOS=linux GOARCH=${GOARCH:-amd64} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "dist/vpnpanel-linux-${GOARCH:-amd64}" .
echo "Fertig: $(pwd)/dist/vpnpanel-linux-${GOARCH:-amd64}"

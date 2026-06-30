#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not reachable for this user."
  echo "Run: sudo usermod -aG docker $USER"
  echo "Then close/reopen the terminal. On Kali, install newgrp with: sudo apt install -y util-linux-extra"
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is missing."
  echo "On Kali, install it with:"
  echo "  sudo apt update && sudo apt install -y docker-compose"
  exit 1
fi

"${COMPOSE[@]}" pull
"${COMPOSE[@]}" up -d

echo
echo "MISP is starting at: https://localhost:8443"
echo "Login: admin@admin.test"
echo "Password: $(grep '^ADMIN_PASSWORD=' .env | cut -d= -f2-)"
echo "API key is configured in ../../.env as MISP_API_KEY."

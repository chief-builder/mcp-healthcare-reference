#!/usr/bin/env bash
# Create <dir>/.env from <dir>/.env.example, replacing every change-me
# placeholder with a random value — what the phase READMEs ask a human to do.
set -euo pipefail
dir="$1"
cp "$dir/.env.example" "$dir/.env"
while IFS= read -r line; do
  case "$line" in
    *=change-me*) key="${line%%=*}"
      sed -i.bak "s|^${key}=.*|${key}=$(openssl rand -hex 16)|" "$dir/.env" ;;
  esac
done < "$dir/.env.example"
rm -f "$dir/.env.bak"

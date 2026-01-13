#!/usr/bin/env bash
# Helper to set a GitHub Actions secret using the `gh` CLI
# Usage examples:
# 1) Interactively (you will be prompted):
#    gh auth login
#    ./scripts/gh-set-secret.sh degeneratesystems thingdb MY_SECRET
# 2) Non-interactive (read value from env):
#    export SECRET_VALUE="sensitive"
#    ./scripts/gh-set-secret.sh degeneratesystems thingdb MY_SECRET --env SECRET_VALUE

set -euo pipefail

if [ $# -lt 3 ]; then
  echo "Usage: $0 <owner> <repo> <secret-name> [--env VAR_NAME | --file /path/to/file]"
  exit 2
fi

OWNER=$1
REPO=$2
NAME=$3
shift 3

VALUE=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --env)
      VAR="$2"
      VALUE="${!VAR:-}"
      shift 2
      ;;
    --file)
      FILE="$2"
      VALUE=$(<"$FILE")
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2; exit 2
      ;;
  esac
done

if [ -z "$VALUE" ]; then
  echo "Enter secret value for $NAME (end with Ctrl-D):"
  VALUE=$(cat -)
fi

# Use `gh` CLI to set the secret for the repository
echo "$VALUE" | gh secret set "$NAME" --repo "$OWNER/$REPO" --body -
echo "Secret $NAME set for $OWNER/$REPO"

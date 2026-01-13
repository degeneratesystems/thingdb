#!/usr/bin/env bash
# Automatic self-hosted runner registration helper
# Usage: set GITHUB_TOKEN to a PAT with repo admin permissions and run as root on the runner host.
# This script will:
#  - create a registration token via the GitHub API
#  - download and extract the actions runner
#  - configure the runner unattended and install as a service

set -euo pipefail

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "Please set GITHUB_TOKEN environment variable with a PAT that has repo admin permissions." >&2
  exit 1
fi

if [ -z "${REPO:-}" ]; then
  echo "Please set REPO environment variable to 'OWNER/REPO' (e.g. degeneratesystems/thingdb)." >&2
  exit 1
fi

RUNNER_DIR=${RUNNER_DIR:-/opt/gh-runner}
mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

echo "Requesting registration token for repository $REPO..."
resp=$(curl -s -X POST -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/repos/$REPO/actions/runners/registration-token")
token=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))")
if [ -z "$token" ]; then echo "Failed to obtain registration token: $resp" >&2; exit 1; fi

echo "Downloading runner package..."
curl -fsSL https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64-$(uname -m).tar.gz | tar -xz

echo "Configuring runner..."
./config.sh --url "https://github.com/$REPO" --token "$token" --unattended --name "$(hostname)-runner"

echo "Installing and starting runner service..."
sudo ./svc.sh install
sudo ./svc.sh start

echo "Runner configured and started."

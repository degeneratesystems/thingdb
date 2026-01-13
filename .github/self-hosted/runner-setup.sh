#!/usr/bin/env bash
# Minimal helper to register a GitHub Actions self-hosted runner on Linux (systemd)
# Usage: edit REPO and TOKEN then run as root on your runner host

REPO="OWNER/thingdb"   # replace OWNER with your GitHub username or org
TOKEN=""               # replace with a registration token from GitHub (set below)
RUNNER_DIR="/opt/gh-runner"

if [ -z "$TOKEN" ]; then
  echo "Please set TOKEN to a registration token from GitHub (see README instructions)."
  exit 1
fi

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

ARCH=$(uname -m)
OS=linux
if [ "$ARCH" = "x86_64" ]; then ARCH= x86_64; fi

echo "Downloading runner..."
curl -fsSL https://github.com/actions/runner/releases/latest/download/actions-runner-$(uname -s)-$(uname -m).tar.gz | tar -xz

echo "Configuring runner (non-interactive)..."
./config.sh --url https://github.com/$REPO --token $TOKEN --unattended --name $(hostname)-runner

echo "Installing service..."
sudo ./svc.sh install
sudo ./svc.sh start

echo "Runner installed and started. Check the repository Settings -> Actions -> Runners to confirm."

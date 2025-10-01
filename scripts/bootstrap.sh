#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
xargs -a configs/apt-requirements.txt -r \
  sudo apt-get install -y --no-install-recommends --allow-downgrades
sudo apt-mark hold $(cut -d= -f1 configs/apt-requirements.txt)

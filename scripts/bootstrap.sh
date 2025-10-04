#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -euo pipefail
sudo apt-get update
xargs -a $SCRIPT_DIR/configs/apt-requirements.txt -r \
  sudo apt-get install -y --no-install-recommends --allow-downgrades
sudo apt-mark hold $(cut -d= -f1 $SCRIPT_DIR/configs/apt-requirements.txt)

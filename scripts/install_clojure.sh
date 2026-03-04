#!/usr/bin/env bash

which clojure
if [[ "$?" == "0" ]]; then
  echo "Clojure already installed"
  exit 0
fi

echo "Installing clojure ..."

set -euo pipefail

curl -L -O https://github.com/clojure/brew-install/releases/latest/download/linux-install.sh
chmod +x linux-install.sh
sudo ./linux-install.sh
rm ./linux-install.sh

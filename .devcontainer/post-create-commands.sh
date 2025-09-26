#!/bin/bash

# add strongswan to safe.directory git global
git config --global --add safe.directory /workspaces/strongswan

bash .devcontainer/conan-setup/install-conan.sh

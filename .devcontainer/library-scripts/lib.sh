#!/bin/bash

apt_get_update() {
	if [ "$(find /var/lib/apt/lists/* | wc -l)" = "0" ]; then
		echo "Running apt-get update..."
		apt-get update -y
	fi
}

# Checks if packages are installed and installs them if not
check_packages() {
	if ! dpkg -s "$@" >/dev/null 2>&1; then
		apt_get_update
		apt-get -y install --no-install-recommends "$@"
	fi
}

apt_cleanup() {
	rm -rf /var/lib/apt/lists/*
}

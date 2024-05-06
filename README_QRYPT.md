# Build strongSwan with liboqs and Qrypt's blast and entropy plugins
## Create a directory to clone the repos into
```
mkdir qrypt
cd qrypt
```

## Clone and build liboqs

```
sudo apt -y install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

mkdir build
cd build
cmake -GNinja -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr \
              -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON ..
ninja
sudo ninja install

cd ../../
```

## Clone the strongSwan repo
```
git clone https://github.com/QryptInc/strongswan.git
cd strongswan
git checkout 6.0.0beta4-qrypt-plugins
```

## Edit the plugin conf files
Create a free account at https://docs.qrypt.com/getting_started/ This will enable you to generate JSON web tokens (JWT) that you'll need to add to the conf files.

strongswan/src/libstrongswan/plugins/quantum_entropy/quantum-entropy.conf:
```
quantum_entropy {
    # Entropy API FQDN
    fqdn = api-eus.qrypt.com

    # Entropy API JWT
    jwt = <PASTE-TOKEN-HERE>

    # File to read local random bytes for xor with downloaded entropy
    random = /dev/random

    # Whether to load the plugin. Can also be an integer to increase the
    # priority of this plugin.
    load = yes
}
```

strongswan/src/libstrongswan/plugins/blast/blast.conf:
```
blast {

    jwt = <PASTE-TOKEN-HERE>

    load = yes

}
```

## Build strongSwan
Building a strongSwan 6.X tag will include support for RFC 9370 which will allow for hybrid key exchanges including PQC and BLAST.

```
sudo apt-get -y install pkg-config shtool autoconf gperf bison build-essential pkg-config m4 libtool libgmp3-dev automake autoconf gettext perl flex libsystemd-dev libjansson-dev curl libcurl4-openssl-dev

./autogen.sh
./configure --enable-openssl --disable-random --prefix=/usr/local --sysconfdir=/etc --enable-systemd --enable-oqs --enable-curl
make
sudo make install

cd ..
```

## Build Qrypt's entropy plugin
```
cd src/libstrongswan/plugins/quantum_entropy
make SWANDIR=../../../..
sudo make install PLUGINCONF=/etc/strongswan.d/charon/
cd ../../../..
```

## Build Qrypt's BLAST plugin
Copy Qrypt's libraries to the proper location
```
cd src/libstrongswan/plugins/blast/
sudo make install-deps
sudo ldconfig
make SWANDIR=../../../..
sudo make install PLUGINCONF=/etc/strongswan.d/charon/
cd ../../../..
```

Set  accept_private_algs = yes in /usr/local/etc/strongswan.conf

## Start and stop service
```
sudo systemctl status strongswan.service
sudo systemctl start strongswan.service
sudo systemctl stop strongswan.service
```

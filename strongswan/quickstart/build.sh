# Build strongswan
pushd .
cd ..
sudo apt-get -y install pkg-config shtool autoconf gperf bison build-essential m4 libtool libgmp3-dev automake gettext perl flex libsystemd-dev libjansson-dev curl libcurl4-openssl-dev redis

./autogen.sh
./configure --enable-openssl --disable-random --prefix=/usr/local --sysconfdir=/etc --enable-systemd --enable-cmd --enable-oqs --enable-curl
make -j
sudo make install
popd

sudo cp ipsec.secrets /etc/ipsec.secrets

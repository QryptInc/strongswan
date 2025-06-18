# Clone and install libOQS
pushd .
sudo apt -y install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

mkdir build
cd build
cmake -GNinja -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr \
              -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON ..
ninja
sudo ninja install
popd

# Clone strongswan
pushd .
git clone https://github.com/QryptInc/strongswan.git
cd strongswan
git checkout BF-6.0.0beta4-qrypt-plugins
cp ../sdk/* src/libstrongswan/plugins/blast/

# Add the following lines to the config file
# 	accept_private_algs = yes
# 	send_vendor_id = yes
mv conf/strongswan.conf conf/strongswan.original.conf
sed 's/yes\n\tplugins/yes\n\taccept_private_algs = yes\n\tsend_vendor_id = yes\n\tplugins/g' conf/strongswan.original.conf > conf/strongswan.conf

popd
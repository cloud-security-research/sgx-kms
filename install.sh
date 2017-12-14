#!/bin/bash

if [ `whoami` != 'root' ]
  then
    echo 'You must be root to execute this.'
    exit
fi

if [ $# -lt 1 ]; then
    echo 'Invalid command'
    echo 'Usage : sudo ./BarbiE.bz2.run <ipv4>'
    echo 'ip    : IPv4 address of the server'
    exit
fi

apt-get update
apt-get install -y python-pip python-dev libffi-dev
pip install cffi

mkdir /var/log/barbican/
CWD=`pwd`
barbican=$CWD"/Server/barbican-stable-mitaka"
cd $barbican
chmod +x install_barbican_with_nginx.sh
./install_barbican_with_nginx.sh $1
cd $CWD

file="/usr/local/lib/python2.7/dist-packages/ecdsa-*"
if [ -f $file ] ; then
   rm $file
fi
git clone https://github.com/warner/python-ecdsa.git
cd $CWD/python-ecdsa
python setup.py install

cd $CWD

cp $CWD/lib/BarbiE.signed.so /usr/local/lib/libBarbiE.signed.so
cp $CWD/lib/libBarbiE_Server.so /usr/local/lib
cp $CWD/lib/libBarbiE_Client.so /usr/local/lib
cp $CWD/lib/libsample_libcrypto.so /usr/local/lib

ldconfig

cd /etc/barbican/vassals
ln -fs /usr/local/lib/libBarbiE.signed.so BarbiE.signed.so

cd $CWD/Server/barbican-stable-mitaka/barbican/barbican/plugin/crypto/
ln -fs /usr/local/lib/libBarbiE.signed.so BarbiE.signed.so
ln -fs $CWD/lib/barbie_client.h barbie_client.h
ln -fs $CWD/lib/barbie_server.h barbie_server.h
ln -fs $CWD/lib/common.h common.h
ln -fs $CWD/lib/ecp.h ecp.h
ln -fs $CWD/lib/ias_ra.h ias_ra.h
ln -fs $CWD/lib/network_ra.h network_ra.h
ln -fs $CWD/lib/ra_client.h ra_client.h
ln -fs $CWD/lib/ra_server.h ra_server.h
ln -fs $CWD/lib/remote_attestation_result.h remote_attestation_result.h
ln -fs $CWD/lib/service_provider.h service_provider.h

cd $CWD/test_scripts
ln -fs /usr/local/lib/libBarbiE.signed.so BarbiE.signed.so
ln -fs $CWD/lib/barbie_client.h barbie_client.h
ln -fs $CWD/lib/barbie_server.h barbie_server.h
ln -fs $CWD/lib/common.h common.h
ln -fs $CWD/lib/ecp.h ecp.h
ln -fs $CWD/lib/ias_ra.h ias_ra.h
ln -fs $CWD/lib/network_ra.h network_ra.h
ln -fs $CWD/lib/ra_client.h ra_client.h
ln -fs $CWD/lib/ra_server.h ra_server.h
ln -fs $CWD/lib/remote_attestation_result.h remote_attestation_result.h
ln -fs $CWD/lib/service_provider.h service_provider.h

cd $CWD


#!/bin/bash

if [ `whoami` != 'root' ]
  then
    echo 'You must be root to execute this.'
    exit
fi

apt-get update
apt-get install -y python-pip python-dev libffi-dev
pip install cffi

CWD=`pwd`

cp $CWD/lib/BarbiE.signed.so /usr/local/lib/libBarbiE.signed.so
cp $CWD/lib/libBarbiE_Server.so /usr/local/lib
cp $CWD/lib/libBarbiE_Client.so /usr/local/lib
cp $CWD/lib/libsample_libcrypto.so /usr/local/lib

ldconfig

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


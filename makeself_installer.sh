#!/bin/bash

apt-get install makeself

CWD=`pwd`

cd $CWD/BarbiE
./deploy.sh
cd $CWD

BarbiE=$CWD"/BarbiE/release"
Client=$CWD"/Barbican/Client"
Server=$CWD"/Barbican/Server"
install_script=$CWD"/install.sh"
uninstall_script=$CWD"/uninstall.sh"
startup_script=$CWD"/startup.sh"
env_file=$CWD"/env.properties"
rabbit_mq_file=$CWD"/rabbit_mq.properties"

target=$CWD"/target"
mkdir $target
mkdir $target/test_scripts
mkdir $target/lib

cp -r $startup_script $target
cp -r $env_file $target
cp -r $rabbit_mq_file $target
cp -r $BarbiE/* $target/lib
cp -r $Client/sgx.py $target/test_scripts/
cp -r $Client/sgx.h $target/test_scripts/
cp -r $Client/legacy_client.py $target/test_scripts/
cp -r $Client/sgx_client_wo_hw.py $target/test_scripts/
cp -r $Client/sgx_client_with_hw.py $target/test_scripts/
cp -r $Client/__init__.py $target/test_scripts/
cp -r $Client/rabbit_mq_scripts/ $target/test_scripts/
cp -r $Server $target
cp -r $install_script $target
cp -r $uninstall_script $target

makeself --bzip2 --target "/opt/BarbiE/" $target BarbiE.bz2.run "Installer for SGX-Barbican server" ./install.sh


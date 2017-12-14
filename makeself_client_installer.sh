#!/bin/bash

apt-get install makeself

CWD=`pwd`

cd $CWD/BarbiE
./deploy.sh
cd $CWD

BarbiE=$CWD"/BarbiE/release"
Client=$CWD"/Barbican/Client"
install_script=$CWD"/install_client.sh"
uninstall_script=$CWD"/uninstall_client.sh"
env_file=$CWD"/env.properties"
rabbit_mq_file=$CWD"/rabbit_mq.properties"

target=$CWD"/target_client"
mkdir $target
mkdir $target/test_scripts
mkdir $target/lib

cp -r $env_file $target
cp -r $rabbit_mq_file $target
cp -r $BarbiE/* $target/lib
cp -r $Client/sgx.py $target/test_scripts/
cp -r $Client/sgx.h $target/test_scripts/
cp -r $Client/sgx_client_wo_hw.py $target/test_scripts/
cp -r $Client/sgx_client_with_hw.py $target/test_scripts/
cp -r $Client/project_policy_mgmt.py $target/test_scripts/
cp -r $Client/__init__.py $target/test_scripts/
cp -r $Client/rabbit_mq_scripts/ $target/test_scripts/
cp -r $install_script $target
cp -r $uninstall_script $target

makeself --bzip2 --target "/opt/BarbiE/" $target BarbiE_client.bz2.run "Installer for SGX-Barbican client" ./install_client.sh


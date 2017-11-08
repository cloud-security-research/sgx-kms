#!/bin/bash

USER=`whoami`

cd /etc/barbican/vassals
ln -s /home/$USER/SGX-Barbican/BarbiE/service_provider/network_ra.h network_ra.h
ln -s /home/$USER/SGX-Barbican/BarbiE/BarbiE.signed.so BarbiE.signed.so

cd /home/$USER/SGX-Barbican/Barbican/Client
ln -s /home/$USER/SGX-Barbican/BarbiE/service_provider/network_ra.h network_ra.h
ln -s /home/$USER/SGX-Barbican/BarbiE/BarbiE.signed.so BarbiE.signed.so

cd /home/$USER/SGX-Barbican/Barbican/Server/barbican-stable-mitaka/barbican/barbican/plugin/crypto/
ln -s /home/$USER/SGX-Barbican/BarbiE/service_provider/network_ra.h network_ra.h
ln -s /home/$USER/SGX-Barbican/BarbiE/BarbiE.signed.so BarbiE.signed.so

cd

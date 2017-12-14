#!/bin/bash

if [ `whoami` != 'root' ]
  then
    echo 'You must be root to execute this.'
    exit
fi

rm -rf /etc/barbican
rm -rf /var/lib/barbican
rm -rf /opt/BarbiE
rm /usr/local/lib/python2.7/dist-packages/ecdsa-*

echo 'Uninstallation complete'

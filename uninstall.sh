#!/bin/bash

if [ `whoami` != 'root' ]
  then
    echo 'You must be root to execute this.'
    exit
fi

rm -rf /etc/barbican
rm -rf /var/lib/barbican
rm -rf /opt/BarbiE

echo 'Uninstallation complete'

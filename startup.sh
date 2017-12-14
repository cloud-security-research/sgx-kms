service nginx $1
sleep 3

sudo /opt/BarbiE/Server/barbican-stable-mitaka/barbican/bin/barbican.sh $1

#!/bin/bash
CURRENT_PATH=$PWD
BARBICAN_INSTALL_PATH="$CURRENT_PATH/barbican"
BARBICAN_SETUP_FILE="$CURRENT_PATH/barbican/bin/barbican.sh"
BARBICAN_COMMAND_FILE="/usr/local/bin/barbican"

if [ $# -eq 0 ]; then
    echo "No arguments provided.. Usage: sudo ./install-barbican-with-nginx.sh <host_ref ip>"
    exit 1
fi

###### Installing system dependencies ######
# Install dependencies required to build Barbican
apt-get install -y python-dev libffi-dev libssl-dev libsqlite3-dev libldap2-dev libsasl2-dev git wget dos2unix python-pip

#Installation for GCM mode
git clone https://github.com/dlitz/pycrypto.git
cd pycrypto
python setup.py install
cd $CURRENT_PATH

# Grant execute permission to barbican setup file
echo "Barbican setup file = $BARBICAN_SETUP_FILE"
chmod +x $BARBICAN_SETUP_FILE

#Make changes to the barbican.sh file to remove dependency on pyenv
echo 'Make changes to the barbican.sh file to remove dependency on pyenv.....'
sed -i 's/ -H $VENV_DIR $PYDEV_DEBUG_PARAM//g' $BARBICAN_SETUP_FILE
sed -i 's/-H $VENV_DIR/\&/g' $BARBICAN_SETUP_FILE #Run start_barbican process in background
sed -i 's/VENV_DIR=${VIRTUAL_ENV:-`pyenv prefix`}//g' $BARBICAN_SETUP_FILE
sed -i 's/python setup.py testr//g' $BARBICAN_SETUP_FILE

echo "Installing packages"
wget https://pypi.python.org/packages/3c/ec/a94f8cf7274ea60b5413df054f82a8980523efd712ec55a59e7c3357cf7c/pyparsing-2.2.0.tar.gz
gunzip pyparsing-2.2.0.tar.gz
tar -xvf pyparsing-2.2.0.tar
cd pyparsing-2.2.0 && python setup.py install

python -m pip install appdirs
pip install docutils
pip install jinja2
pip install wrapt
pip install netaddr
pip install rfc3986
pip install monotonic
pip install pyyaml
pip install singledispatch
pip install positional
pip install greenlet
pip install functools32
pip install fasteners
pip install kombu
pip install netifaces
pip install cachetools

cd $BARBICAN_INSTALL_PATH
# Install Barbican
echo 'Start Installing Barbican...'
bin/barbican.sh install
sleep 10
bin/barbican.sh stop

###### Installing Nginx ######
# Install dependencies for uwsgi and nginx server
apt-get install -y uwsgi uwsgi-plugin-python nginx-full

#Create a virtual host configuration file
cd /etc/nginx/sites-available
touch barbican

cat > barbican << EOL
server {
            listen          443;
            server_name     $1;
            access_log /srv/www/barbican/logs/access.log;
            error_log /srv/www/barbican/logs/error.log;
            ssl on;
            ssl_certificate /etc/nginx/ssl_keys/server.crt;
            ssl_certificate_key /etc/nginx/ssl_keys/server.key;

            location / {
                   include         uwsgi_params;
                   uwsgi_pass      127.0.0.1:9311;
                   #uwsgi_read_timeout 300;
            }
    }
EOL

#Link the virtual host file to sites-enabled
ln -s /etc/nginx/sites-available/barbican /etc/nginx/sites-enabled/barbican

#Remove the default virtual host
rm /etc/nginx/sites-enabled/default

#Create directory for web server logs
mkdir -p /srv/www/barbican/logs

#Create directory for ssl keys
mkdir -p /etc/nginx/ssl_keys
cd /etc/nginx/ssl_keys
openssl genrsa -out server.key 2048
echo "SSL Certificate Generation Began....Please provide following details:"
openssl req -new -key server.key -out server.csr -sha256
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

cd /etc/barbican/vassals
sed -i 's/protocol = http/protocol = uwsgi/g' barbican-api.ini

cd /etc/nginx
cat >> uwsgi_params << EOL
uwsgi_param     SCRIPT_NAME             '';
EOL

#Alter the host reference used in api's
cd /etc/barbican
sed -i "s/host_href = http:\/\/localhost:9311/host_href = https:\/\/$1:443/g" ~/barbican.conf

mkdir /var/log/barbican/

#Restart nginx service
service nginx restart
echo "Nginx installed successfully... Start barbican with /opt/BarbiE/startup.sh script..!!"

cd $CURRENT_PATH

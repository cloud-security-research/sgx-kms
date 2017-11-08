FROM ubuntu:14.04

RUN apt-get update

RUN apt-get install -y python-dev libffi-dev libssl-dev libsqlite3-dev libldap2-dev libsasl2-dev git python-pip

RUN mkdir /root/barbican
RUN git clone -b stable/mitaka https://github.com/openstack/barbican.git /root/barbican

RUN sed -i 's/ -H $VENV_DIR $PYDEV_DEBUG_PARAM//g' /root/barbican/bin/barbican.sh
RUN sed -i 's/-H $VENV_DIR//g' /root/barbican/bin/barbican.sh 
RUN sed -i 's/VENV_DIR=${VIRTUAL_ENV:-`pyenv prefix`}//g' /root/barbican/bin/barbican.sh
RUN sed -i 's/python setup.py testr//g' /root/barbican/bin/barbican.sh

RUN chmod +x /root/barbican/bin/barbican.sh
WORKDIR /root/barbican
RUN sed -i '99d' bin/barbican.sh
RUN bin/barbican.sh install
WORKDIR /

RUN apt-get install -y uwsgi uwsgi-plugin-python nginx-full

COPY barbican /etc/nginx/sites-available/barbican
RUN ln -s /etc/nginx/sites-available/barbican /etc/nginx/sites-enabled/barbican
RUN rm /etc/nginx/sites-enabled/default

RUN mkdir -p /srv/www/barbican/logs

RUN mkdir -p /etc/nginx/ssl_keys
RUN openssl genrsa -out /etc/nginx/ssl_keys/server.key 2048
RUN openssl req -new -key /etc/nginx/ssl_keys/server.key -out /etc/nginx/ssl_keys/server.csr -subj "/C=us/ST=or/L=us/O=intel/OU=labs/CN=example.com"
RUN openssl x509 -req -days 365 -in /etc/nginx/ssl_keys/server.csr -signkey /etc/nginx/ssl_keys/server.key -out /etc/nginx/ssl_keys/server.crt

RUN sed -i 's/protocol = http/protocol = uwsgi/g' /etc/barbican/vassals/barbican-api.ini

RUN echo "uwsgi_param     SCRIPT_NAME             '';" >> /etc/nginx/uwsgi_params

RUN sed -i "s/host_href = http:\/\/localhost:9311/host_href = https:\/\/localhost:443/g" /root/barbican.conf

COPY rc.local /tmp/rc.local

RUN cat /tmp/rc.local > /etc/rc.local

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/etc/rc.local; /root/barbican/bin/barbican.sh start"]

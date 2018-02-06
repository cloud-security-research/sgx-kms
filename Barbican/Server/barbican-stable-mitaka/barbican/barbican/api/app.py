# Copyright (c) 2013-2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
API application handler for Barbican
"""
import os
import socket
import pecan
import sys
from netifaces import AF_INET
import netifaces as ni
import requests
import json

try:
    import newrelic.agent
    newrelic_loaded = True
except ImportError:
    newrelic_loaded = False

from oslo_log import log

from barbican.api.controllers import versions
from barbican.api import hooks
from barbican.common import config
from barbican import i18n as u
from barbican.model import repositories
from barbican import queue
from barbican.plugin.crypto.sgx import SGXInterface

CONF = config.CONF
kek_file = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "plugin/crypto/masterkey")

if newrelic_loaded:
    newrelic.agent.initialize(
        os.environ.get('NEW_RELIC_CONFIG_FILE', '/etc/newrelic/newrelic.ini'),
        os.environ.get('NEW_RELIC_ENVIRONMENT')
    )


def build_wsgi_app(controller=None, transactional=False):
    """WSGI application creation helper

    :param controller: Overrides default application controller
    :param transactional: Adds transaction hook for all requests
    """
    request_hooks = [hooks.JSONErrorHook()]
    if transactional:
        request_hooks.append(hooks.BarbicanTransactionHook())
    if newrelic_loaded:
        request_hooks.insert(0, hooks.NewRelicHook())

    # Create WSGI app
    wsgi_app = pecan.Pecan(
        controller or versions.AVAILABLE_VERSIONS[versions.DEFAULT_VERSION](),
        hooks=request_hooks,
        force_canonical=False
    )
    # clear the session created in controller initialization     60
    repositories.clear()
    return wsgi_app


def main_app(func):
    def _wrapper(global_config, **local_conf):
        # Queuing initialization
        queue.init(CONF, is_server_side=False)

        # Configure oslo logging and configuration services.
        log.setup(CONF, 'barbican')

        config.setup_remote_pydev_debug()

        # Initializing the database engine and session factory before the app
        # starts ensures we don't lose requests due to lazy initialization of
        # db connections.
        repositories.setup_database_engine_and_factory()

        wsgi_app = func(global_config, **local_conf)

        if newrelic_loaded:
            wsgi_app = newrelic.agent.WSGIApplicationWrapper(wsgi_app)
        LOG = log.getLogger(__name__)
        LOG.info(u._LI('Barbican app created and initialized'))
        return wsgi_app
    return _wrapper


@main_app
def create_main_app(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application."""
    # Setup app with transactional hook enabled
    return build_wsgi_app(versions.V1Controller(), transactional=True)

@main_app
def create_main_app2(global_config, **local_conf):
    """uWSGI factory method for the Barbican-API application."""
    # Setup app with transactional hook enabled
    get_or_generate_master_key()
    return build_wsgi_app(versions.V2Controller(), transactional=True)

def get_or_generate_master_key():
    SGX = SGXInterface()
    master = SGX.get_master_ip()
    SGX.init_env_variables()
    enclave_id = SGX.init_enclave(SGX.barbie_c)
    if is_master(master):
        kek = generate_key(SGX, enclave_id)
    else:
        kek_url = 'https://' + master + ':443/v2/kek'
        if os.path.isfile(kek_file):
            with open(kek_file, 'r') as f:
                kek = f.read()
        else:
	        kek =  get_kek(SGX, enclave_id, kek_url)
        if kek == None or kek == "":
            kek =  get_kek(SGX, enclave_id, kek_url)

    with open(kek_file, 'w') as f:
        f.write(kek)

    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

def generate_key(SGX=None, enclave_id=None):
    if os.path.isfile(kek_file):
        with open(kek_file, 'r') as f:
            kek = f.read()
    else:
        print "********* Generating Master key ************"
        return SGX.generate_key(SGX.barbie_c, enclave_id, 16).value
    if kek == None or kek == "":
        print "********* Generating Master key ************"
        return SGX.generate_key(SGX.barbie_c, enclave_id, 16).value
    else:
        print "********* Using Existing Master key ************"
        return kek

def get_kek(SGX=None,enclave_id=None, kek_url=None):
    print "*********Requesting for Master key ************"
    response, cookies = provision_kek(kek_url, None)
    return response['kek']

def is_master(master_ip):
    if master_ip == None or master_ip == "":
        return True
    interface_list = ni.interfaces()
    for interface in interface_list:
        if master_ip == get_ip_address(interface):
            return True
    return False

def get_ip_address(ifname):
        try:
            return ni.ifaddresses(ifname)[AF_INET][0]['addr']
        except Exception as e:
            print "Cannot get IP Address for Interface %s" % ifname
            sys.exit(1)

def provision_kek(kek_url, cookie):
    return do_get(kek_url, cookie)

def do_get(url, cookie=None):
    session = requests.Session()
    post_headers = { "content-type" : "application/json", "X-Project-Id" : "admin"}
    r = session.get(url, headers=post_headers, cookies=cookie, verify=False)
    if r.ok:
        return r.json(), r.cookies.get_dict()
    else:
        print r
        raise Exception("Error in POST call")

def create_version_app(global_config, **local_conf):
    wsgi_app = pecan.make_app(versions.VersionsController())
    return wsgi_app

import argparse
import json
import requests
import sys
import base64

from test_scripts.sgx import Secret, SGXInterface
from test_scripts.rabbit_mq_scripts.RabbitMq import RabbitMq

proj_id = None
attestation_url = None
SK = None
SGX = None

def get_msg0_msg1():
    data = {}
    response, cookie = do_post(attestation_url, data)
    return response, cookie

def proc_msg0(msg0):
    ret, p_net_ctxt = SGX.proc_msg0(SGX.barbie_c, msg0)
    return p_net_ctxt

def get_msg2(msg1, ctxt):
    return SGX.proc_msg1_gen_msg2(SGX.barbie_c, msg1, ctxt)

def get_msg3(msg2, cookie=None):
    data = { "msg2" : msg2 }
    response, cookie = do_post(attestation_url, data, cookie)
    return response['msg3'], cookie

def get_msg4(msg3, ctxt, sk, project_id=None):
    return SGX.legacy_proc_msg3_gen_msg4(SGX.barbie_c, msg3, ctxt, sk, project_id)

def get_status(msg4, ctxt=None, policy=None, e_mr_e_list=None, cookie=None):
    if policy:
        data = { "msg4" : msg4, "policy" : policy, "mr_e_list" : " ".join(e_mr_e_list) }
    else:
        data = { "msg4" : msg4 }
    response, cookie = do_post(attestation_url, data, cookie)
    return response.get('session_key', None), response['status'], cookie

def do_attestation(policy=None, e_mr_e_list=None):
    global SK
    print "******************************Performing Attestation******************************"
    print "Step 1: Challenge BarbiE."
    resp, route = get_msg0_msg1()
    msg0 = resp['msg0']
    msg1 = resp['msg1']
    ctxt = proc_msg0(msg0)
    print "msg1 : " + msg1
    msg2 = get_msg2(msg1, ctxt)
    print "msg2 : " + msg2
    msg3, cookie = get_msg3(msg2, cookie=route)
    print "msg3 : " + msg3
    msg4 = get_msg4(msg3, ctxt, Secret("", len("")), proj_id)
    print "msg4 : " + msg4
    print "Step 2: BarbiE identity verified."
    dh_sk, status, cookie = get_status(msg4, None, policy, e_mr_e_list, cookie=route)
    if status != 0:
        raise Exception(status)
    SK = SGX.get_sk(SGX.barbie_c, ctxt, dh_sk)
    if int(status) == 0:
        print "Step 3: Symmetric key securely provisioned."
        print "TEST PASSED : Attestation"
        with open(proj_id + "_sk", 'w') as f:
            f.write(SK.value)
    else:
        print "TEST FAILED : Attestation"
    return cookie

def do_publish_msg(enclave_id):
    print "******************************Publishing Message*****************************"
    queue = raw_input("Provide Queue Name : ")
    msg = raw_input("Enter the message to be publish : ")
    with open(proj_id + "_sk", "r") as f:
        SK = f.read()
    enc_msg = SGX.legacy_encrypt(SGX.barbie_c, Secret(SK, len(SK)), Secret(msg, len(msg)))
    rbc=RabbitMq()
    rbc.publish(enc_msg, queue)
    print "******************************Publishing Complete*****************************"

def do_post(url, data, cookie=None):
    session = requests.Session()
    post_headers = { "content-type" : "application/json", "X-Project-Id" : proj_id}
    r = session.post(url, headers=post_headers, data=json.dumps(data), cookies=cookie, verify=False)
    if r.ok:
        return r.json(), r.cookies.get_dict()
    else:
        print r
        raise Exception("Error in POST call")

def do_get(url, cookie=None):
    session = requests.Session()
    get_headers = { "Accept" : "text/plain", "X-Project-Id" : proj_id}
    r = session.get(url, headers=get_headers, cookies=cookie, verify=False)
    if r.ok:
        return r.text, r.cookies.get_dict()
    else:
        print r
        raise Exception("Error in GET call")

def get_mr_e_list(mr_e_list_file):
    mr_e_list = None
    with open(mr_e_list_file) as f:
        mr_e_list = f.readlines()
    mr_e_list = [mr_e.strip() for mr_e in mr_e_list]
    return mr_e_list

def get_enc_mr_e_list(mr_e_list):
    global SK
    e_mr_e_list = []
    for b64_mr_e in mr_e_list:
        mr_e = base64.b64decode(b64_mr_e)
        e_mr_e = SGX.legacy_encrypt(SGX.barbie_c, SK, Secret(mr_e, len(mr_e)))
        e_mr_e_list.append(e_mr_e)
    return e_mr_e_list

def main(args):
    global attestation_url
    global SK

    ip = args['ip_address']
    attestation_url = 'https://' + ip + ':443/v2/attestation'

    global proj_id
    proj_id = args['project_id']

    global SGX

    SGX = SGXInterface()
    SGX.init_env_variables()

    enclave_id = SGX.init_enclave(SGX.barbie_c)

    policy = args.get('policy', None)
    if policy:
        sk_value = None
        with open(proj_id + "_sk", "r") as f:
            sk_value = f.read()
        plain_sk_len = 16
        SK = Secret(sk_value, plain_sk_len)
        mr_e_list = get_mr_e_list(args.get('mr_e_file', None))
        e_mr_e_list = get_enc_mr_e_list(mr_e_list)
        do_attestation(policy, e_mr_e_list)
        print("Policy for project is Set")
        return

    is_admin = args.get('admin', None)
    if is_admin:
        cookie = do_attestation()
    else:
        do_publish_msg(enclave_id)

    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--admin', action='store_true', help='Run command only to perform Attestation')
    parser.add_argument('-ip', '--ip_address', metavar='', help='Barbican Server IP. Connects with localhost if not provided.', default='127.0.0.1')
    parser.add_argument('-p', '--project_id', metavar='', help='Project ID', required=True)
    parser.add_argument('-po', '--policy', choices=['3'], metavar='', help='Project policy')
    parser.add_argument('-mre', '--mr_e_file', metavar='', help='Absolute path of file with list of base64 encoded MR ENCLAVEs')
    args = parser.parse_args()
    main(vars(args))

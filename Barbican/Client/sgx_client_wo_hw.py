import argparse
import json
import requests
import sys
import base64

from sgx import Secret, SGXInterface

proj_id = None
attestation_url = None
secret_url = None
kek_url = None
SK = None
SGX = None

def get_msg0_msg1():
    data = {}
    response, cookie = do_post(attestation_url, data)
    return response, cookie

def proc_msg0(msg0, spid=None, client_verify_ias=False):
    ret, p_net_ctxt = SGX.proc_msg0(SGX.barbie_c, msg0, spid, client_verify_ias)
    return p_net_ctxt

def get_msg2(msg1, ctxt):
    return SGX.proc_msg1_gen_msg2(SGX.barbie_c, msg1, ctxt)

def get_msg3(msg2, cookie=None, client_verify_ias=False, server_verify_ias=False):
    data = { "msg2" : msg2, "client_verify_ias" : client_verify_ias, "server_verify_ias" : server_verify_ias}
    response, cookie = do_post(attestation_url, data, cookie)
    status = response['status']
    if status != "OK":
        raise Exception(status)
    if all(resp in response for resp in ('resp_crt', 'resp_sign', 'resp_body')):
        crt, cacrt = SGX.get_crt(response['resp_crt'])
        try:
            SGX.verify_certificate(crt, cacrt)
            SGX.verify_signature(crt, response['resp_sign'], response['resp_body'])
        except Exception as e:
           raise e
    return response['msg3'], cookie

def get_msg4(msg3, ctxt, sk, project_id=None, ias_crt=None, client_verify_ias=False):
    return SGX.legacy_proc_msg3_gen_msg4(SGX.barbie_c, msg3, ctxt, sk, project_id, ias_crt, client_verify_ias)

def get_status(msg4, ctxt=None, policy=None, e_mr_e_list=None, mr_signer=None, cookie=None):
    if policy:
        if e_mr_e_list:
            data = { "msg4" : msg4, "policy" : policy, "mr_e_list" : " ".join(e_mr_e_list) }
        else:
            data = { "msg4" : msg4, "policy" : policy, "mr_signer" : mr_signer }
    else:
        data = { "msg4" : msg4 }
    response, cookie = do_post(attestation_url, data, cookie)
    return response.get('session_key', None), response['status'], cookie

def do_attestation(policy=None, e_mr_e_list=None, mr_signer=None, SPID=None, IAS_CRT=None, client_verify_ias=False, server_verify_ias=False):
    global SK

    print "******************************Performing Attestation******************************"
    print "Step 1: Challenge BarbiE."
    resp, route = get_msg0_msg1()
    msg0 = resp['msg0']
    print msg0
    msg1 = resp['msg1']
    ctxt = proc_msg0(msg0, SPID, client_verify_ias)
    print "msg1 : " + msg1
    msg2 = get_msg2(msg1, ctxt)
    print "msg2 : " + msg2
    msg3, cookie = get_msg3(msg2, cookie=route, client_verify_ias=client_verify_ias, server_verify_ias=server_verify_ias)
    print "msg3 : " + msg3
    msg4 = get_msg4(msg3, ctxt, Secret("", len("")), proj_id, IAS_CRT, client_verify_ias)
    print "msg4 : " + msg4
    print "Step 2: BarbiE identity verified."
    dh_sk, status, cookie = get_status(msg4, None, policy, e_mr_e_list, mr_signer, cookie=route)
    if status != "OK":
        raise Exception(status)
    SK = SGX.get_sk(SGX.barbie_c, ctxt, dh_sk)
    if status == "OK":
        print "Step 3: Symmetric key securely provisioned."
        print "TEST PASSED : Attestation"
        with open(proj_id + "_sk", 'w') as f:
            f.write(SK.value)
    else:
        print "TEST FAILED : Attestation"
    return cookie

def store_secret(secret):
    data = {"payload" : secret, "payload_content_type": "text/plain"}
    response, cookie = do_post(secret_url, data)
    return response['secret_ref']

def retrieve_secret(ref):
    url = ref + "/payload"
    response, cookie = do_get(ref)
    return response

def provision_kek(enc_kek, cookie):
    data = {"kek" : enc_kek}
    do_post(kek_url, data, cookie)

def do_provision_kek(cookie):
    print "***************************Performing KEK Provisioning*************************************"
    plain_kek = raw_input("Enter the KEK to be provisioned for barbican(16 byte): ")
    print "Step 0: Client created KEK: [" + plain_kek + "]"
    kek = Secret(plain_kek, len(plain_kek))
    print "Step 1: Encrypt the KEK with the shared symmetric key."
    enc_kek = SGX.legacy_encrypt(SGX.barbie_c, SK, kek)
    print "Step 2: Send the encrypted KEK to barbican"
    provision_kek(enc_kek, cookie)
    print "****************************Provisioning Completeted***************************************"

def do_secret_mgmt():
    with open(proj_id + "_sk", "r") as f:
        SK = f.read()
    print "******************************Performing Secret Management*****************************"
    plain_secret = raw_input("Enter the secret to be stored in the barbican : ") 
    print "Step 0: Client created secret: [" + plain_secret + "]"
    secret = Secret(plain_secret, len(plain_secret))
    print "Step 1: Encrypt the secret with the shared symmetric key."
    sk_secret = SGX.legacy_encrypt(SGX.barbie_c, Secret(SK, len(SK)), secret)
    print "Step 2: Store the secret and get the reference."
    ref = store_secret(sk_secret)
    print "Secret reference: " + ref
    print "Step 3: Retrieve the secret encrypted with shared secret."
    enc_secret = retrieve_secret(ref)
    if SGX.compare_secret(SGX.barbie_c, sk_secret[40:], enc_secret[40:], secret.length):
        print "TEST PASSED : Secret management"
    else:
        print "TEST FAILED : Secret management"

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
    global secret_url
    global kek_url
    global SK

    ip = args['ip_address']
    attestation_url = 'https://' + ip + ':443/v2/attestation'
    secret_url = 'https://' + ip + ':443/v2/secrets'
    kek_url = 'https://' + ip + ':443/v2/kek'

    SPID = args['spid']
    if args.get('client_verify_ias', False) and args.get('server_verify_ias', False):
        client_verify_ias = True
        server_verify_ias = False
    else:
        client_verify_ias = args.get('client_verify_ias', False)
        server_verify_ias = args.get('server_verify_ias', False)

    IAS_CRT = args['ias_crt']
    global proj_id
    proj_id = args['project_id']

    global SGX

    SGX = SGXInterface()
    SGX.init_env_variables()

    enclave_id = SGX.init_enclave(SGX.barbie_c)

    policy = args.get('policy', None)
    if policy:
        e_mr_e_list = None
        mr_signer = None
        if policy == "3":
            mr_e_list = args.get('mr_e_file', None)
            if not mr_e_list:
                print "Error : Please provide MR ENCLAVE list file using -mre"
                return
            sk_value = None
            with open(proj_id + "_sk", "r") as f:
                sk_value = f.read()
            plain_sk_len = 16
            SK = Secret(sk_value, plain_sk_len)
            mr_e_list = get_mr_e_list(mr_e_list)
            e_mr_e_list = get_enc_mr_e_list(mr_e_list)
        else:
            mr_signer = args.get('mr_signer', None)
            if not mr_signer:
                print "Error : Please provide Mr SIGNER using -mrs"
                return
        do_attestation(policy, e_mr_e_list, mr_signer, SPID=SPID, IAS_CRT=IAS_CRT, client_verify_ias=client_verify_ias, server_verify_ias=server_verify_ias)
        return

    is_admin = args.get('admin', None)
    if is_admin:
        cookie = do_attestation(SPID=SPID, IAS_CRT=IAS_CRT, client_verify_ias=client_verify_ias, server_verify_ias=server_verify_ias)
        do_provision_kek(cookie)
    else:
        cookie = do_attestation(SPID=SPID, IAS_CRT=IAS_CRT, client_verify_ias=client_verify_ias, server_verify_ias=server_verify_ias)
        do_secret_mgmt()

    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--admin', action='store_true', help='Run command as admin user for KEK provisioning')
    parser.add_argument('--client_verify_ias', action='store_true', help='If provided client will contact IAS to verify quote')
    parser.add_argument('--server_verify_ias', action='store_true', help='If provided server will contact IAS to verify quote')
    parser.add_argument('-ip', '--ip_address', help='Barbican Server IP. Defaults to localhost', default='127.0.0.1')
    parser.add_argument('-p', '--project_id', help='Project ID', required=True)
    parser.add_argument('-s', '--spid', help='SPID provided by IAS in hexstring format')
    parser.add_argument('-crt', '--ias_crt', help='Certificate for IAS server')
    parser.add_argument('-po', '--policy', choices=['1', '3'], metavar='', help='Project policy')
    parser.add_argument('-mre', '--mr_e_file', help='Absolute path of file with list of MR ENCLAVEs')
    parser.add_argument('-mrs', '--mr_signer', help='Base64 encoded MR SIGNER')
    args = parser.parse_args()
    main(vars(args))

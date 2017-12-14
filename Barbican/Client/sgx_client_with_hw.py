import argparse
import json
import base64
import requests
import sys

from sgx import Secret, SGXInterface

proj_id = None
mutual_attestation_url = None
secret_url = None
order_url = None
SK = None
SGX = None
key_dir = None

def get_msg0_msg1(is_remote, url, pub_key, enclave_id=None, spid=None):
    if is_remote:
        data ={"pub_key" : pub_key}
        response, cookie = do_post(url, data)
        return response, cookie

    ret, c_msg0 = SGX.gen_msg0(SGX.barbie_c, spid)
    p_ctxt, c_msg1 = SGX.gen_msg1(SGX.barbie_c, enclave_id, pub_key)
    return c_msg0, c_msg1, p_ctxt

def proc_msg0(msg0, spid=None, client_verify_ias=False):
    ret, p_net_ctxt = SGX.proc_msg0(SGX.barbie_c, msg0, spid, client_verify_ias)
    return p_net_ctxt

def get_msg2(msg1, ctxt, priv_key):
    return SGX.proc_msg1_gen_msg2(SGX.barbie_c, msg1, ctxt, priv_key)

def get_msg3(is_remote, msg2, ctxt=None, cookie=None, enclave_id=None,
             ias_crt=None, client_verify_ias=False, server_verify_ias=False):
    if is_remote:
        data = { "msg2" : msg2 }
        response, cookie = do_post(attestation_url, data, cookie)
        return response['msg3'], cookie

    return SGX.proc_msg2_gen_msg3(SGX.barbie_c, enclave_id, msg2, ctxt, ias_crt, client_verify_ias, server_verify_ias)

def get_msg4(enclave_id, msg3, ctxt, s_nonse, c_msg3, project_id=None, owner_mr_e=None, ias_crt=None, client_verify_ias=False):
    return SGX.proc_msg3_gen_msg4(SGX.barbie_c, enclave_id, msg3, ctxt, s_nonse, c_msg3, project_id, owner_mr_e, ias_crt, client_verify_ias)

def get_status(msg4, ctxt=None, cookie=None, enclave_id=None, sealed_nonse=None):
    return SGX.proc_msg4(SGX.barbie_c, enclave_id, msg4, ctxt, sealed_nonse)

def get_msg2_msg3(c_msg0, c_msg1, s_msg2, client_verify_ias=False, server_verify_ias = False):
    data = {'c_msg0' : c_msg0, 'c_msg1' : c_msg1, 's_msg2' : s_msg2, "client_verify_ias" : client_verify_ias, "server_verify_ias" : server_verify_ias }
    response, cookie = do_post(mutual_attestation_url, data)
    status = response['status']
    if status != "OK":
        raise Exception(status)
    if all(resp in response for resp in ('s_resp_crt', 's_resp_sign', 's_resp_body')):
        crt, cacrt = SGX.get_crt(response['s_resp_crt'])
        try:
            SGX.verify_certificate(crt, cacrt)
            SGX.verify_signature(crt, response['s_resp_sign'], response['s_resp_body'])
        except Exception as e:
           raise e
    return response['c_msg2'], response['s_msg3']

def get_msg4_status(c_msg3, s_msg4, c_resp_crt=None, c_resp_sign=None, c_resp_body=None):
    data = {'c_msg3' : c_msg3, 's_msg4' : s_msg4}
    if c_resp_crt and c_resp_sign and c_resp_body:
        data['c_resp_crt'] = c_resp_crt
        data['c_resp_sign'] = c_resp_sign
        data['c_resp_body'] = c_resp_body
    response, cookie = do_post(mutual_attestation_url, data)
    return response.get('c_msg4', None), response['status']

def do_mutual_attestation(enclave_id, owner_mr_e=None, SPID=None, IAS_CRT=None, client_verify_ias=False, server_verify_ias=False):
    global SK

    print "************************* Mutual Attestation ********************************************"

    global key_dir
    c_pub_key, c_priv_key = SGX.generate_key_pair(key_dir)

    resp, cookie = get_msg0_msg1(True, mutual_attestation_url, c_pub_key)
    s_msg0 = resp['s_msg0']
    s_msg1 = resp['s_msg1']
    s_pub_key = resp['s_pub_key']

    print "Server msg0 : " + s_msg0
    print "Server msg1 : " + s_msg1

    s_p_net_ctxt = proc_msg0(s_msg0, SPID, client_verify_ias)
    s_msg2 = get_msg2(s_msg1, s_p_net_ctxt, c_priv_key)
    print "Server msg2 : " + s_msg2

    c_msg0, c_msg1, c_p_ctxt = get_msg0_msg1(False, mutual_attestation_url, s_pub_key, enclave_id=enclave_id, spid=SPID)
    print "Client msg0 : " + c_msg0
    print "Client msg1 : " + c_msg1

    c_msg2, s_msg3 = get_msg2_msg3(c_msg0, c_msg1, s_msg2, client_verify_ias, server_verify_ias)
    print "Client msg2 : " + c_msg2
    print "Server msg3 : " + s_msg3

    c_msg3, c_resp_crt, c_resp_sign, c_resp_body = get_msg3(False, c_msg2, c_p_ctxt, enclave_id=enclave_id, ias_crt=IAS_CRT, client_verify_ias=client_verify_ias, server_verify_ias=server_verify_ias)
    print "Client msg3 : " + c_msg3

    sealed_nonse = SGX.generate_key(SGX.barbie_c, enclave_id, 16)
    s_msg4 = get_msg4(enclave_id, s_msg3, s_p_net_ctxt, sealed_nonse, c_msg3, proj_id, owner_mr_e, IAS_CRT, client_verify_ias)
    print "Server msg4 : " + s_msg4

    c_msg4, s_status = get_msg4_status(c_msg3, s_msg4, c_resp_crt, c_resp_sign, c_resp_body)
    if s_status != "OK":
        raise Exception(s_status)
    print "Server Status : " + s_status
    print "Client msg4 : " + c_msg4

    c_status, sealed_sk = get_status(c_msg4, c_p_ctxt, enclave_id=enclave_id, sealed_nonse=sealed_nonse)
    if int(c_status) == 0 and s_status == "OK":
        print "TEST PASSED : Mutual Attestation"
        with open(proj_id + "_sk", 'w') as f:
            f.write(sealed_sk)
    else:
        print "TEST FAILED : Mutual Attestation"
    print "Client Status : " + str(c_status)
    plain_sk_len = 16
    sealed_len = SGX.barbie_c.get_sealed_data_len(enclave_id, 0, plain_sk_len)
    SK = Secret(sealed_sk, sealed_len)


def store_secret(secret):
    data = {"payload" : secret, "payload_content_type": "text/plain"}
    response, cookie = do_post(secret_url, data)
    return response['secret_ref']

def retrieve_secret(ref):
    url = ref + "/payload"
    response, cookie = do_get(ref)
    return response

def do_secret_mgmt(enclave_id, args):
    print "******************************Performing Secret Mngmt*****************************"
    secret_ref = args.get('secret_ref', None)
    with open(proj_id + "_sk", "r") as f:
        SK = f.read()
    sk_secret = None
    if not secret_ref:
        sealed_secret = SGX.generate_key(SGX.barbie_c, enclave_id, 16)
        print "Step 0: Client generated secret: [" + sealed_secret.value + "]"
        print "Step 1: Encrypt the secret with the shared symmetric key."
        plain_sk_len = 16
        sealed_len = SGX.barbie_c.get_sealed_data_len(enclave_id, 0, plain_sk_len)
        sk_secret = SGX.transport(SGX.barbie_c, enclave_id, Secret(SK, sealed_len), sealed_secret, None)
        print "Step 2: Store the secret and get the reference."
        secret_ref = store_secret(sk_secret)
    print "Secret reference: " + secret_ref
    print "Step 3: Retrieve the secret encrypted with shared secret."
    enc_secret = retrieve_secret(secret_ref)
    if args['secret_ref']:
        plain_secret = base64.b64decode(SGX.decrypt(SGX.barbie_c, enclave_id, Secret(SK, len(SK)), enc_secret))
        print "Step 4: Client retrieved the secret : " + plain_secret
        return
    if sk_secret and SGX.compare_secret(SGX.barbie_c, sk_secret[40:], enc_secret[40:], 16):
        print "TEST PASSED : Secret management"
    else:
        print "TEST FAILED : Secret management"

def generate_order():
    data = {"type" : "key", "meta" : {"algorithm" : "aes", "bit_length": 128, "mode": "cbc", "payload_content_type": "application/octet-stream"}}
    response, cookie = do_post(order_url, data)
    return response['order_ref']

def retrieve_order(ref):
    url = ref
    response, cookie = do_get_order(ref)
    return retrieve_secret(response['secret_ref'])

def do_order_mgmt(enclave_id):
    print "******************************Performing Order Mngmt*****************************"
    order_ref = generate_order()
    print "Step 0: Client generated order : " + order_ref

    do_mutual_attestation(enclave_id, "0")

    sk_secret = retrieve_order(order_ref)
    print "Step 2: SK encrypted secret recieved : " + str(sk_secret)
    #sealed_secret = SGX.provision_kek(SGX.barbie_c, enclave_id, SK, sk_secret)
    #print "Step 3: Sealed secret : " + str(sealed_secret)

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

def do_get_order(url, cookie=None):
    session = requests.Session()
    get_headers = { "Content-Type" : "application/json", "X-Project-Id" : proj_id}
    r = session.get(url, headers=get_headers, cookies=cookie, verify=False)
    if r.ok:
        return r.json(), r.cookies.get_dict()
    else:
        print r
        raise Exception("Error in GET call")

def main(args):
    global mutual_attestation_url
    global secret_url
    global order_url
    global SK

    global key_dir

    key_dir = args['key_dir']

    ip = args['ip_address']
    owner_mr_e = args.get('owner_mr_e', None)

    mutual_attestation_url = 'https://' + ip + ':443/v2/mutual_attestation'
    secret_url = 'https://' + ip + ':443/v2/secrets'
    order_url = 'https://' + ip + ':443/v2/orders'

    SPID = args['spid']
    client_verify_ias = args.get('client_verify_ias', False)
    server_verify_ias = args.get('server_verify_ias', False)
    IAS_CRT = args['ias_crt']

    global proj_id
    proj_id = args['project_id']

    global SGX
    SGX = SGXInterface()
    SGX.init_env_variables()

    enclave_id = SGX.init_enclave(SGX.barbie_c)
    do_mutual_attestation(enclave_id, owner_mr_e, SPID, IAS_CRT, client_verify_ias, server_verify_ias)
    do_secret_mgmt(enclave_id, args)
    #do_order_mgmt(enclave_id)

    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--ip_address', help='Barbican Server IP. Connects with localhost if not provided.', default='127.0.0.1')
    parser.add_argument('-p', '--project_id', help='Project ID', required=True)
    parser.add_argument('-s', '--spid', help='SPID provided by IAS in hexstring format', required=True)
    parser.add_argument('-crt', '--ias_crt', help='Certificate for IAS server', required=True)
    parser.add_argument('--client_verify_ias', action='store_true', help='If provided client will contact IAS to verify quote')
    parser.add_argument('--server_verify_ias', action='store_true', help='If provided server will contact IAS to verify quote')
    parser.add_argument('-ref', '--secret_ref', help='Reference path of the secret. If not provided, secret will be first generated and using its reference path retrieved.')
    parser.add_argument('-o_mr_e', '--owner_mr_e', help='Owner MR Enclave who created the project', required=True)
    parser.add_argument('-kdir', '--key_dir', help='Key pair directory path')
    args = parser.parse_args()
    main(vars(args))

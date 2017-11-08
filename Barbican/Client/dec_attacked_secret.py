import base64
from Crypto.Cipher import AES
import json
import requests
import sys

from sgx import Secret, SGXInterface

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

def get_msg4(msg3, ctxt, sk):
    return SGX.legacy_proc_msg3_gen_msg4(SGX.barbie_c, msg3, ctxt, sk)

def get_status(msg4, ctxt=None, cookie=None):
    data = { "msg4" : msg4 }
    response, cookie = do_post(attestation_url, data, cookie)
    return response.get('session_key', None), response['status'], cookie

def do_attestation():
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
    msg4 = get_msg4(msg3, ctxt, Secret("", len("")))
    print "msg4 : " + msg4
    print "Step 2: BarbiE identity verified."
    dh_sk, status, cookie = get_status(msg4, cookie=route)
    if status != 0:
        raise Exception(status)
    SK = SGX.get_sk(SGX.barbie_c, ctxt, dh_sk)
    if int(status) == 0:
        print "Step 3: Symmetric key securely provisioned."
        print "TEST PASSED : Attestation"
    else:
        print "TEST FAILED : Attestation"
    return cookie

def dec_secret(enc_secret):
    obj = AES.new(SK.value, AES.MODE_GCM, base64.b64decode(enc_secret[:16]))
    print "Decrypted Secret : " + obj.decrypt(base64.b64decode(enc_secret[40:]))
    
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

def main(args):
    global attestation_url

    ip = args[0]
    attestation_url = 'https://' + ip + ':443/v2/attestation'

    global proj_id
    proj_id = args[1]

    global SGX

    SGX = SGXInterface()
    SGX.init_env_variables()

    enclave_id = SGX.init_enclave(SGX.barbie_c)

    cookie = do_attestation()
    dec_secret(args[2])

    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print "Syntax : python dec_attacked_secret.py <IP> <proj_id> <enc_secret>"
    else:
        main(sys.argv[1:])

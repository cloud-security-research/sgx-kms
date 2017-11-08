import json
import requests
import sys

from sgx import SGXInterface

#Temporary changes to hide warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

proj_id = None
attestation_url = None
mutual_attestation_url = None
secret_url = None
kek_url = None
SK = None
SGX = None

def get_msg1(is_remote, url=None):
    if is_remote:
        data = {}
        response, cookie = do_post(url, data)
        return response, cookie

    return SGX.gen_msg1()

def get_msg2(msg1):
    return SGX.proc_msg1_gen_msg2(msg1)

def get_msg3(is_remote, msg2, ctxt=None, cookie=None):
    if is_remote:
        data = { "msg2" : msg2 }
        response, cookie = do_post(attestation_url, data, cookie)
        return response['msg3'], cookie

    return SGX.proc_msg2_gen_msg3(msg2, ctxt)

def get_msg4(msg3, ctxt, sk):
    return SGX.proc_msg3_gen_msg4(msg3, ctxt, sk)

def get_status(is_remote, msg4, ctxt=None, cookie=None, provision_kek=False):
    if is_remote:
        data = None
        if provision_kek:
            data = { "msg4" : msg4 , "provision_kek" : "True"}
        else:
            data = { "msg4" : msg4 }
        response, cookie = do_post(attestation_url, data, cookie)
        return response['status'], cookie
    return SGX.proc_msg4(msg4, ctxt)

def get_msg2_msg3(c_msg1, s_msg2):
    data = {'c_msg1' : c_msg1, 's_msg2' : s_msg2}
    response, cookie = do_post(mutual_attestation_url, data)
    return response['c_msg2'], response['s_msg3']

def get_msg4_status(c_msg3, s_msg4):
    data = {'c_msg3' : c_msg3, 's_msg4' : s_msg4}
    response, cookie = do_post(mutual_attestation_url, data)
    return response['c_msg4'], response['status']

def do_mutual_attestation():

    print "************************* Mutual Attestation ********************************************"

    resp, cookie = get_msg1(True, mutual_attestation_url)
    s_msg1 = resp['s_msg1']

    print "Server msg1 : " + s_msg1

    ctxt1, s_msg2 = get_msg2(s_msg1)
    print "Server msg2 : " + s_msg2
    ctxt2, c_msg1 = get_msg1(False)
    print "Client msg1 : " + c_msg1

    c_msg2, s_msg3 = get_msg2_msg3(c_msg1, s_msg2)
    print "Client msg2 : " + c_msg2
    print "Server msg3 : " + s_msg3

    s_msg4 = get_msg4(s_msg3, ctxt1, SK)
    print "Server msg4 : " + s_msg4
    c_msg3 = get_msg3(False, c_msg2, ctxt2)
    print "Client msg3 : " + c_msg3

    c_msg4, s_status = get_msg4_status(c_msg3, s_msg4)
    print "Client msg4 : " + c_msg4
    print "Server Status : " + s_status

    c_status, sealed_sk = get_status(False, c_msg4, ctxt2)
    print "Client Status : " + str(c_status)

    print "Server generated SK : " + sealed_sk
    if int(c_status) == 0 and s_status == "OK":
        print "TEST PASSED : Mutual Attestation"
    else:
        print "TEST FAILED : Mutual Attestation"

def do_attestation(provision_kek=False):
    print "******************************Performing Attestation******************************"
    print "Step 1: Challenge BarbiE."
    resp, route = get_msg1(True, attestation_url)
    msg1 = resp['msg1']
    print "msg1 : " + msg1
    ctxt, msg2 = get_msg2(msg1)
    print "msg2 : " + msg2
    msg3, cookie = get_msg3(True, msg2, cookie=route)
    print "msg3 : " + msg3
    msg4 = get_msg4(msg3, ctxt, SK)
    print "msg4 : " + msg4
    print "Step 2: BarbiE identity verified."
    status, cookie = get_status(True, msg4, cookie=route, provision_kek=provision_kek)
    if int(status) == 0:
        print "Step 3: Symmetric key securely provisioned."
        print "TEST PASSED : Attestation"
        with open(proj_id + "_sk", 'w') as f:
            f.write(SK)
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
    kek = raw_input("Enter the KEK to be provisioned for barbican enclave(16 byte): ")
    print "Step 0: client created KEK: [" + kek + "]"
    print "Step 1: Encrypt the KEK with the shared symmetric key."
    with open(proj_id + "_sk", "r") as f:
        SK = f.read()
    enc_kek = SGX.encrypt(SK, kek)
    print "Step 2: Send the encrypted KEK to barbican"
    provision_kek(enc_kek, cookie)
    print "****************************Provisioning Completeted***************************************"

def do_secret_mgmt():
    print "******************************Performing Secret Mngmt*****************************"
    sealed_secret = SGX.generate_key()
    print "Step 0: client created secret: [" + sealed_secret + "]"
    print "Step 1: Encrypt the secret with the shared symmetric key."
    with open(proj_id + "_sk", "r") as f:
        SK = f.read()
    sk_secret = SGX.transport(SK, sealed_secret)
    with open("post_enc_" + proj_id + ".data", 'w') as f:
        post_data = {"payload":sk_secret , "payload_content_type":"text/plain"}
        post_data = json.dumps(post_data)
        f.write(post_data)
    ref = store_secret(sk_secret)
    print "Step 2: Store the secret and get the reference."
    print "\tBarbican server decrypted secret with symmetric key, encypted with seal key, and wrote to DB."
    print "Stored secret reference: " + ref
    enc_secret = retrieve_secret(ref)
    print "Step 3: Retrieve the secret encrypted with shared secret."
    print "\tBarbican server decrypted secret that was read from DB with with seal key, encrypted with symmetric key."
    if SGX.compare_secret(sk_secret, enc_secret):
        print "Step 4: Secret [" + enc_secret + "] received and ready for consumption."
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

def main(args):
    global attestation_url
    global mutual_attestation_url
    global secret_url
    global kek_url
    ip = args[0]

    attestation_url = 'https://' + ip + ':443/v2/attestation'
    mutual_attestation_url = 'https://' + ip + ':443/v2/mutual_attestation'
    secret_url = 'https://' + ip + ':443/v2/secrets'
    kek_url = 'https://' + ip + ':443/v2/kek'

    global proj_id
    proj_id = args[1]

    global SK
    global SGX
    SGX = SGXInterface()

    SGX.init_enclave()
    SK = SGX.generate_key()
    print "Client generated SK : " + SK

    if args[2] == "admin":
        cookie = do_attestation(True)
        do_provision_kek(cookie)
    else:
        cookie = do_attestation()
        do_secret_mgmt()

    #do_mutual_attestation()
    SGX.destroy_enclave()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print "Please provide project id"
        print "Syntax : python sgx_client.py <IP> <proj_id> <user/admin>"
    else:
        main(sys.argv[1:])

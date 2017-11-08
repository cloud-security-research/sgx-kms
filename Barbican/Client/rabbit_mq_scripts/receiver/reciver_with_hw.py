import argparse
import json
import base64
import requests
import sys

from test_scripts.sgx import Secret, SGXInterface
from test_scripts.rabbit_mq_scripts.RabbitMq import RabbitMq

proj_id = None
mutual_attestation_url = None
SK = None
SGX = None

def get_msg0_msg1(is_remote, url=None, enclave_id=None):
    if is_remote:
        data = {}
        response, cookie = do_post(url, data)
        return response, cookie

    ret, c_msg0 = SGX.gen_msg0(SGX.barbie_c)
    p_ctxt, c_msg1 = SGX.gen_msg1(SGX.barbie_c, enclave_id)
    return c_msg0, c_msg1, p_ctxt

def proc_msg0(msg0):
    ret, p_net_ctxt = SGX.proc_msg0(SGX.barbie_c, msg0)
    return p_net_ctxt

def get_msg2(msg1, ctxt):
    return SGX.proc_msg1_gen_msg2(SGX.barbie_c, msg1, ctxt)

def get_msg3(is_remote, msg2, ctxt=None, cookie=None, enclave_id=None):
    if is_remote:
        data = { "msg2" : msg2 }
        response, cookie = do_post(attestation_url, data, cookie)
        return response['msg3'], cookie

    return SGX.proc_msg2_gen_msg3(SGX.barbie_c, enclave_id, msg2, ctxt)

def get_msg4(enclave_id, msg3, ctxt, sk, project_id=None):
    return SGX.proc_msg3_gen_msg4(SGX.barbie_c, enclave_id, msg3, ctxt, sk, project_id)

def get_status(msg4, ctxt=None, cookie=None, enclave_id=None):
    return SGX.proc_msg4(SGX.barbie_c, enclave_id, msg4, ctxt)

def get_msg2_msg3(c_msg0, c_msg1, s_msg2):
    data = {'c_msg0' : c_msg0, 'c_msg1' : c_msg1, 's_msg2' : s_msg2}
    response, cookie = do_post(mutual_attestation_url, data)
    return response['c_msg2'], response['s_msg3']

def get_msg4_status(c_msg3, s_msg4, policy, e_mr_e_list=None):
    if policy:
        if e_mr_e_list:
            data = {'c_msg3' : c_msg3, 's_msg4' : s_msg4, 'policy' : policy, 'mr_e_list' : ' '.join(e_mr_e_list)}
        else:
            data = {'c_msg3' : c_msg3, 's_msg4' : s_msg4, 'policy' : policy}
    else:
        data = {'c_msg3' : c_msg3, 's_msg4' : s_msg4}
    response, cookie = do_post(mutual_attestation_url, data)
    return response.get('c_msg4', None), response['status']

def do_mutual_attestation(enclave_id, policy=None, e_mr_e_list=None):
    global SK

    print "************************* Mutual Attestation ********************************************"

    resp, cookie = get_msg0_msg1(True, mutual_attestation_url)
    s_msg0 = resp['s_msg0']
    s_msg1 = resp['s_msg1']

    print "Server msg0 : " + s_msg0
    print "Server msg1 : " + s_msg1

    s_p_net_ctxt = proc_msg0(s_msg0)
    s_msg2 = get_msg2(s_msg1, s_p_net_ctxt)
    print "Server msg2 : " + s_msg2

    c_msg0, c_msg1, c_p_ctxt = get_msg0_msg1(False, enclave_id=enclave_id)
    print "Client msg0 : " + c_msg0
    print "Client msg1 : " + c_msg1

    c_msg2, s_msg3 = get_msg2_msg3(c_msg0, c_msg1, s_msg2)
    print "Client msg2 : " + c_msg2
    print "Server msg3 : " + s_msg3

    s_msg4 = get_msg4(enclave_id, s_msg3, s_p_net_ctxt, None, proj_id)
    print "Server msg4 : " + s_msg4
    c_msg3 = get_msg3(False, c_msg2, c_p_ctxt, enclave_id=enclave_id)
    print "Client msg3 : " + c_msg3

    c_msg4, s_status = get_msg4_status(c_msg3, s_msg4, policy, e_mr_e_list)
    if s_status != "OK":
        raise Exception(s_status)
    print "Server Status : " + s_status
    print "Client msg4 : " + c_msg4

    c_status, sealed_sk = get_status(c_msg4, c_p_ctxt, enclave_id=enclave_id)
    print "Client Status : " + str(c_status)
    plain_sk_len = 16
    sealed_len = SGX.barbie_c.get_sealed_data_len(enclave_id, 0, plain_sk_len)
    SK = Secret(sealed_sk, sealed_len)

    if int(c_status) == 0 and s_status == "OK":
        print "TEST PASSED : Mutual Attestation"
        with open(proj_id + "_sk", 'w') as f:
            f.write(SK.value)
    else:
        print "TEST FAILED : Mutual Attestation"

def do_recive_msg(enclave_id):
    print "******************************Reciving Message*****************************"
    queue = raw_input("Provide Queue Name : ")
    rbc=RabbitMq()
    enc_msg = rbc.receive(queue)
    with open(proj_id + "_sk", "r") as f:
        SK = f.read()
    dec_msg = SGX.decrypt(SGX.barbie_c, enclave_id, Secret(SK, len(SK)), enc_msg)
    print "Encrypted message recieved is :" + enc_msg
    print "Decrypted messgae recived is :" + base64.b64decode(dec_msg)
    print "******************************Recived Message*****************************"
    

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

def get_enc_mr_e_list(mr_e_list, enclave_id):
    global SK
    e_mr_e_list = []
    for b64_mr_e in mr_e_list:
        mr_e = base64.b64decode(b64_mr_e)
        e_mr_e = SGX.encrypt(SGX.barbie_c, enclave_id, SK, Secret(mr_e, len(mr_e)))
        e_mr_e_list.append(e_mr_e)
    return e_mr_e_list

def main(args):
    global mutual_attestation_url
    global SK
    ip = args['ip_address']

    mutual_attestation_url = 'https://' + ip + ':443/v2/mutual_attestation'

    global proj_id
    proj_id = args['project_id']

    global SGX
    SGX = SGXInterface()
    SGX.init_env_variables()

    enclave_id = SGX.init_enclave(SGX.barbie_c)
    policy = args.get('policy', None)
    if policy:
        e_mr_e_list=args.get('mr_e_file', None)
        if policy == "3":
            sk_value = None
            with open(proj_id + "_sk", "r") as f:
                sk_value = f.read()
            plain_sk_len = 16
            sealed_len = SGX.barbie_c.get_sealed_data_len(enclave_id, 0, plain_sk_len)
            SK = Secret(sk_value, sealed_len)
            mr_e_list = get_mr_e_list(args.get('mr_e_file', None))
            e_mr_e_list = get_enc_mr_e_list(mr_e_list, enclave_id)
        do_mutual_attestation(enclave_id, policy, e_mr_e_list)
    else:
        do_mutual_attestation(enclave_id, policy)
        do_recive_msg(enclave_id)
    
    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--ip_address', metavar='', help='Barbican Server IP. Connects with localhost if not provided.', default='127.0.0.1')
    parser.add_argument('-p', '--project_id', metavar='', help='Project ID', required=True)
    parser.add_argument('-po', '--policy', choices=['1', '2', '3'], metavar='', help='Project policy')
    parser.add_argument('-mre', '--mr_e_file', metavar='', help='Absolute path of file with list of MR ENCLAVEs')
    args = parser.parse_args()
    main(vars(args))


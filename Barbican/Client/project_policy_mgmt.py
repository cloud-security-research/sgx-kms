import argparse
import json
import requests
import sys
import base64

from sgx import Secret, SGXInterface

proj_id = None
policy_url = None
SK = None
SGX = None

def store_policy(policy, attribute):
    data = {"policy" : policy, "attribute" : attribute}
    response, cookie = do_post(policy_url, data)
    return response

def retrieve_policy():
    response, cookie = do_get(policy_url)
    return response

def do_policy_management(policy, attribute, target_lib, enclave_id):
    global SK
    print "******************************Performing Policy Management******************************"
    if policy:
        print "Storing Policy"
        response = store_policy(policy, attribute)
        if response['status'] == 'OK':
            print "Status : " + response['status']
        else:
            raise Exception("Error : " + response['status'])
    else:
        print "Retrieving Existing Policy"
        response = json.loads(retrieve_policy())
        if response.get('policy', None):
            print "Policy : " + str(response['policy'])
            print response['attribute']
            if(SK.length == SGX.barbie_c.get_sealed_data_len(enclave_id, 0, 16)):
                b64_att = SGX.decrypt(target_lib, enclave_id, SK, response['attribute'])
            else:
                b64_att = SGX.legacy_decrypt(SK.value, response['attribute'])
            full = base64.b64decode(b64_att)
            total_mr =  len(full)/32
            for x in range(0, total_mr):
                print base64.b64encode(full[x*32:(x+1)*32])
            print "Attribute : " + b64_att
        else:
            raise Exception("Error : " + response['status'])
    
    print "*******************************Policy Management Complete*******************************"

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
    get_headers = { "content-type" : "application/json", "X-Project-Id" : proj_id}
    r = session.get(url, headers=get_headers, cookies=cookie, verify=False)
    if r.ok:
        return r.text, r.cookies.get_dict()
    else:
        print r
        raise Exception("Error in GET call")

def get_attribute(attribute_file):
    attribute = None
    with open(attribute_file) as f:
        attribute = f.readlines()
    attribute = [att.strip() for att in attribute]
    return attribute

def get_sk_attribute(attribute, enclave_id):
    global SK
    sk_att_buff = SGX.ffi.new("uint8_t[]", len(attribute) * 32)
    n = 0
    for b64_att in attribute:
        att = SGX.ffi.from_buffer(base64.b64decode(b64_att))
        SGX.ffi.memmove(sk_att_buff + n, att, 32)
        n = n + 32
	
    if(SK.length == SGX.barbie_c.get_sealed_data_len(enclave_id, 0, 16)):
        sk_att = SGX.encrypt(SGX.barbie_c, enclave_id, SK, Secret(sk_att_buff, len(sk_att_buff)))
    else:
        sk_att = SGX.legacy_encrypt(SGX.barbie_c, SK, Secret(sk_att_buff, len(sk_att_buff)))
    return sk_att

def main(args):
    global policy_url, SK, proj_id, SGX
    plain_sk_len = 16
    ip = args['ip_address']
    policy_url = 'https://' + ip + ':443/v2/policy'
    proj_id = args['project_id']

    SGX = SGXInterface()
    SGX.init_env_variables()

    enclave_id = SGX.init_enclave(SGX.barbie_c)

    sk_value = None
    with open(proj_id + "_sk", "r") as f:
        sk_value = f.read()
    if(len(SGX.ffi.from_buffer(sk_value)) !=  plain_sk_len):
        sk_len = SGX.barbie_c.get_sealed_data_len(enclave_id, 0, plain_sk_len)
    else:
        sk_len = plain_sk_len
    SK = Secret(sk_value, sk_len)

    policy = args.get('policy', None)
    attribute = None
    if policy:
        attribute_file = args.get('attribute_file', None)
        if not attribute_file:
            print "Error : Please provide file path with attribute for corresponding policy"
            return
        attribute = get_attribute(attribute_file)
        attribute = get_sk_attribute(attribute, enclave_id)

    do_policy_management(policy, attribute, SGX.barbie_c, enclave_id)

    SGX.destroy_enclave(SGX.barbie_c, enclave_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--ip_address', help='Barbican Server IP. Defaults to localhost', default='127.0.0.1')
    parser.add_argument('-p', '--project_id', help='Project ID', required=True)
    parser.add_argument('-po', '--policy', choices=['1', '2', '3'], metavar='', help='Project policy')
    parser.add_argument('-att', '--attribute_file', help='Absolute path of file with base64 encoded MR Enclave, MR Signer or list of MR Enclaves. Add valid data in file according to the policy provided')
    args = parser.parse_args()
    main(vars(args))

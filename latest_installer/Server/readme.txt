****************************************** README ****************************************************


-------------------------------------BarbiE Installation----------------------------------------------
Execute "BarbiE.bz2.run" script as root user with IP address as parameter
    sudo ./BarbiE.bz2.run <ip_v4_address>
This will prompt for details during SSL certification generation.
Once done the Barbican will be started after installation is complete.
------------------------------------------------------------------------------------------------------

Prerequisite

1) Provide properties in the /opt/BarbiE/env.properties file
  *Required Properties are BARBICAN_ENCLAVE_PATH, IAS_URL, IAS_CRT_PATH, IAS_SPID for Barbican in different lines
  Example:
         BARBICAN_ENCLAVE_PATH=/opt/BarbiE/lib
         IAS_URL=https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/report
         IAS_CRT_PATH=/root/client.pem
         IAS_SPID=76508EJNCLBLB8DS19AC35I5U7XDV828
         IAS_ENABLED=True/False
         KEY_PAIR_DIR=/path/to/store/keypair
         MASTER=/ip/of/master/node
******IAS_URL, IAS_CRT_PATH, IAS_SPID are required for quote validation for BarbiE server. Other wise Attestation will Fail*********
******KEY_PAIR_DIR  Directory path to create server key pair if not exists. Otherwise uses already available key pair
******IAS_CRT_PATH  It contains the path of certificate file to interact with IAS. This file will contain both certificate and private key.
******MASTER IP of master node for scaled barbican setup.

----------------------------------Barbican start/stop/restart-----------------------------------------
/opt/BarbiE/startup.sh start/stop/restart
------------------------------------------------------------------------------------------------------


---------------------------------Testing Barbican SGX Integration-------------------------------------
Go under /opt/BarbiE/test_scripts/
    sudo python sgx.py <SPID> <CRT_PATH>

SPID     : SPID provided by IAS in hexstring format
CRT_PATH : Absolute path of certificate for IAS server
KDIR     : Directory path to save client key pair
------------------------------------------------------------------------------------------------------

[] :- Optional arguments.
-----------------------------------------Sample Commands----------------------------------------------

1. SGX Aware client without SGX Hardware
    a. Attestation and Secret management
        sudo python sgx_client_wo_hw.py -ip [<IP>] -p <proj_id> -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias] -kdir /path/to/key/
        IP                : IPv4 address of the server. Default :- localhost
        proj_id           : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID              : SPID provided by IAS in hexstring format. Required only when we are providing 'client_verify_ias'
        IAS_CRT           : Absolute path of certificate for IAS server. This file will contain both certificate and private key. Required only when we are providing 'client_verify_ias'
        kdir              : Directory path to store generated key pair

    b. Policy Management
        sudo python project_policy_mgmt.py -ip [<IP>] -p <proj_id> -po [<policy>] -att [<attribute>]
        IP        : IPv4 address of the server. Default :- localhost
        proj_id   : Project ID
        policy    : Project Policy to be set.
                    Accepted values :-
                    1 :- Mr Signer of the Client is validated.
                    2 :- Mr Enclave of the Client is validated.
                    3 :- Mr Enclave of the Client is validated with a list of third party enclaves.
        attribute : Path of the file containing base64 encoded Mr Enclave or Mr Signer or list of Mr Enclave. First line of file will contain owner's Mr enclave.
        **NOTE** Owner is that enclave who created the project.

2. SGX Aware client with SGX Hardware
    a. Mutual attestation and Secret Management, Policy Management
        sudo python sgx_client_with_hw.py -ip [<IP>] -p <proj_id> -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias] -o_mr_e [<owner_mr_enclave>] -kdir /path/to/key/
        IP                : IPv4 address of the server. Default :- localhost
        proj_id           : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID              : SPID provided by IAS in hexstring format
        IAS_CRT           : Absolute path of certificate for IAS server. This file will contain both certificate and private key. Required only when we are providing 'client_verify_ias'
        owner_mr_enclave  : Mr enclave of that enclave who created the project.
        kdir              : Directory path to store generated key pair

    b. Policy Management
        sudo python project_policy_mgmt.py -ip [<IP>] -p <proj_id> -po [<policy>] -att [<attribute>]

        IP        : IPv4 address of the server. Default :- localhost
        proj_id   : Project ID
        policy    : Project Policy to be set.
                    Accepted values :-
                    1 :- Mr Signer of the Client is validated.
                    2 :- Mr Enclave of the Client is validated.
                    3 :- Mr Enclave of the Client is validated with a list of third party enclaves.
        attribute : Path of the file containing base64 encoded Mr Enclave or Mr Signer or list of Mr Enclave. First line of file will contain owner's Mr enclave.
        **NOTE** Owner is that enclave who created the project.
-----------------------------------------Sample Commands Examples-------------------------------------
1. SGX Aware client without SGX Hardware

    a. Provision Kek. Server will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 --server_verify_ias --admin -kdir /root/key_path
    b. Attestation and Secret management. Client will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias -kdir /root/key_path
    c. Attestation and Secret management. Server will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj --server_verify_ias -kdir /root/key_path
    d. Attestation and Secret management. If server is not configured to verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj -kdir /root/key_path
    e. Set policy
       python project_policy_mgmt.py -ip 172.21.25.7 -p admin_proj -po 3 -att att_list -kdir /root/key_path
    f. Get policy
       python project_policy_mgmt.py -ip 172.21.25.9 -p admin_proj -kdir /root/key_path

2. SGX Aware client with SGX Hardware

    a. Mutual attestation and Secret Management. Client will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias -o_mr_e TNADWxG05c+BiFxw/AbUu/swa8qhBuBRAK/cA61avL8= -kdir /root/key_path
    b.  Mutual attestation and Secret Management. Server will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --server_verify_ias -o_mr_e TNADWxG05c+BiFxw/AbUu/swa8qhBuBRAK/cA61avL8= -kdir /root/key_path
    c. Mutual attestation and Secret Management. If server is not configured to verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem -o_mr_e TNADWxG05c+BiFxw/AbUu/swa8qhBuBRAK/cA61avL8= -kdir /root/key_path
    d. Set policy
       python project_policy_mgmt.py -ip 172.21.25.9 -p admin_proj -po 3 -att att_list -kdir /root/key_path
    e. Get policy
       python project_policy_mgmt.py -ip 172.21.25.9 -p admin_proj -kdir /root/key_path
------------------------------------------------------------------------------------------------------
***** NOTE *****
The above test scripts are for standalone use of barbican. If barbican is configured with Keystone, the
client scripts wont work.

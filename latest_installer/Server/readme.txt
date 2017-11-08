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
******IAS_URL, IAS_CRT_PATH, IAS_SPID are required for quote validation other wise Attestation will Fail*********

----------------------------------Barbican start/stop/restart-----------------------------------------
/opt/BarbiE/startup.sh start/stop/restart
------------------------------------------------------------------------------------------------------


---------------------------------Testing Barbican SGX Integration-------------------------------------
Go under /opt/BarbiE/test_scripts/
    sudo python sgx.py <SPID> <CRT_PATH>

SPID     : SPID provided by IAS in hexstring format
CRT_PATH : Absolute path of certificate for IAS server
------------------------------------------------------------------------------------------------------

[] :- Optional arguments.
-----------------------------------------Sample Commands----------------------------------------------
1. Provision Master key in Barbican
    sudo python sgx_client_wo_hw.py -ip [<IP>] -p <proj_id> [--admin] -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias]
    IP      : IPv4 address of the server. Default :- localhost
    proj_id : Project ID
    client_verify_ias : Client will call IAS for quote verification.
    server_verify_ias : Server will call IAS for quote verification.
    SPID    : SPID provided by IAS in hexstring format. Required only when we are providing 'client_verify_ias'
    IAS_CRT : Absolute path of certificate for IAS server. Required only when we are providing 'client_verify_ias'

2. SGX Aware client without SGX Hardware
    a. Provision Master key in Barbican
        sudo python sgx_client_wo_hw.py -ip [<IP>] -p <proj_id> [--admin] -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias]
        IP      : IPv4 address of the server. Default :- localhost
        proj_id : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID    : SPID provided by IAS in hexstring format. Required only when we are providing 'client_verify_ias'
        IAS_CRT : Absolute path of certificate for IAS server. Required only when we are providing 'client_verify_ias'

    b. Attestation and Secret management
        sudo python sgx_client_wo_hw.py -ip [<IP>] -p <proj_id> -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias]
        IP      : IPv4 address of the server. Default :- localhost
        proj_id : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID    : SPID provided by IAS in hexstring format. Required only when we are providing 'client_verify_ias'
        IAS_CRT : Absolute path of certificate for IAS server. Required only when we are providing 'client_verify_ias'
    c. Policy Management
        sudo python sgx_client_wo_hw.py -ip [<IP>] -p <proj_id> -po [<policy>] -mre [<mr_enclave_list_file_path>] -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias]
        IP      : IPv4 address of the server. Default :- localhost
        proj_id : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        policy  : Project Policy to be set. Along with policy, MR Signer or path of file with list of MR Enclaves
                  that are base64 encoded needs to be provided.
                  Accepted values :-
                  1 :- Mr Signer of the Client is validated.
                  3 :- Mr Enclave of the Client is validated with a list of third party enclaves.
        SPID    : SPID provided by IAS in hexstring format. Required only when we are providing 'client_verify_ias'
        IAS_CRT : Absolute path of certificate for IAS server. Required only when we are providing 'client_verify_ias'

3. SGX Aware client with SGX Hardware
    a. Mutual attestation and Secret Management, Policy Management
        sudo python sgx_client_with_hw.py -ip [<IP>] -p <proj_id> -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias]
        IP      : IPv4 address of the server. Default :- localhost
        proj_id : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID    : SPID provided by IAS in hexstring format
        IAS_CRT : Absolute path of certificate for IAS server

    b. Policy Management
        sudo python sgx_client_with_hw.py -ip [<IP>] -p <proj_id> -po [<policy>] -mre [<mr_enclave_list_file_path>] -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias]
        policy  : Project Policy to be set. Mandatory during first mutual attestation. If provided in
                  the subsequent call, client will be validated with existing policy and the project 
                  policy will be updated. When policy '3' is provided, path of file with list of MR enclaves
                  that are base64 encoded needs to be provided.
                  Accepted values :-
                  1 :- Mr Signer of the Client is validated.
                  2 :- Mr Enclave of the Client is validated.
                  3 :- Mr Enclave of the Client is validated with a list of third party enclaves.
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID    : SPID provided by IAS in hexstring format
        IAS_CRT : Absolute path of certificate for IAS server

-----------------------------------------Sample Commands Examples-------------------------------------
1. SGX Aware client without SGX Hardware

    a. Provision Kek. Client will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias --admin
    b. Provision Kek. Server will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 --server_verify_ias --admin
    c. Attestation and Secret management. Client will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias
    d. Attestation and Secret management. Server will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj --server_verify_ias
    e. Attestation and Secret management. If server is not configured to verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj
    f. Providing Policy 3 to project. Client will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias -po 3 -mre /root/Mr_list
    g. Providing Policy 3 to project. Server will verify Quote with IAS
        python sgx_client_wo_hw.py -ip 172.21.25.9 -p admin_proj  --server_verify_ias -po 3 -mre /root/Mr_list

2. SGX Aware client with SGX Hardware

    a. Mutual attestation and Secret Management. Client will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias
    b.  Mutual attestation and Secret Management. Server will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --server_verify_ias
    c. Mutual attestation and Secret Management. If server is not configured to verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem
    d. Providing Policy 1 to project. Client will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias -po 1
    e. Providing Policy 1 to project. Server will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --server_verify_ias -po 1
    f. Providing Policy 2 to project. Client will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias -po 2
    g. Providing Policy 2 to project. Server will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --server_verify_ias -po 2
    h. Providing Policy 3 to project. Client will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --client_verify_ias -po 3 -mre /root/Mr_list
    i. Providing Policy 3 to project. Server will verify Quote with IAS
        python sgx_client_with_hw.py -ip 172.21.25.9 -p admin_proj -s 76508EJNCLBLB8DS19AC35I5U7XDV828 -crt /root/client.pem --server_verify_ias -po 3 -mre /root/Mr_list

------------------------------------------------------------------------------------------------------
***** NOTE *****
The above test scripts are for standalone use of barbican. If barbican is configured with Keystone, the
client scripts wont work.

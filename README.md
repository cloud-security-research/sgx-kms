## SGX Enabled OpenStack Barbican Key Management System

> :warning: **DISCONTINUATION OF PROJECT** - 
> *This project will no longer be maintained by Intel.
> **This project has been identified as having known security escapes.**
> Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.*

> **Intel no longer accepts patches to this project.**
> *If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.*

This software is a research proof of concept and not tested for production use

## Create Barbican Enclave Installer

**IMPORTANT: This project is tested with Ubuntu version 16.04. Please make sure to have Intel(R) SGX SDK version 1.8 or 1.9 installed and tested before proceeding.

** IMPORTANT: Please register with Intel(R) IAS service and obtain your own SPID. You will need the SPID, the self signed client certificate and private key for a successful deployment of the SGX Barbican Server.
 
**IMPORTANT: Generate and copy an Intel(R) SGX enclave signing/private key into BarbiE/isv_enclave/isv_enclave_private.pem. optionally you can copy the isv_enclave_private.pem from SGX SDK sample programs.

**IMPORTANT: please install libjsoncpp-dev is not already installed

Execute this
 
```
   sudo ./makeself_installer.sh
```

This will build the Barbican Enclave and will also create **BarbiE.bz2.run** installer binary

## Barbican Enclave Installation

Execute "BarbiE.bz2.run" as root user on the machine where you want to setup Barbican with IP address as argument

```
    sudo ./BarbiE.bz2.run <ip_v4_address>
```

During installation it will prompt for details for self signed SSL certificate generation. For testing, press enter to skip entering details 

**** during installation it will start the server temporarily and indicate some missing components. This is normal **** 


## Startup the Server

Once installation is successful, SGX Barbican server will be installed in /opt/BarbiE folder

To test the installation, go inside /opt/BarbiE and execute

```
    sudo ./startup.sh restart
```


### Pre-requisite

* Note: Master KEK (that is used to encrypt Project wide KEKs) is now automatically generated inside SGX Barbican Enclave. Project wide KEKs are also generated inside SGX Barbican Enclave upon project creation. Hence, the step for KEK provisioning by admin is no longer required during initialization.

* The file /opt/BarbiE/environment contains important parameters for the server. All parameters are mandatory 

  *Required Properties are **BARBICAN_ENCLAVE_PATH**, **IAS_URL**, **IAS_CRT_PATH**, **IAS_SPID**, **IAS_ENABLED** for Barbican on different lines*

```
  Example:
         BARBICAN_ENCLAVE_PATH=/opt/BarbiE/lib
         IAS_URL=https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/report
         IAS_CRT_PATH=/root/client.pem
         IAS_SPID=76508EJNCLBLB8DS19AC35I5U7XDV828
         IAS_ENABLED=True
         KEY_PAIR_DIR=/path/to/dir
	 MASTER=ip/of/master_node 	
```

**IAS_ENABLED** : Enables/disables communication of server with IAS for quote verification and signing.

**IAS_URL, IAS_CRT_PATH, IAS_SPID ** : are required for quote validation for BarbiE server other wise Attestation will Fail.

**KEY_PAIR_DIR ** : Directory path to create server Intel(R) SGX remote attestation ECDSA key pair if not exists. Otherwise uses already available key pair with filenames public_key.pem and private_key.pem in the KEY_PAIR_DIR folder.

**IAS_CRT_PATH ** : It contains the path of certificate file to interact with IAS. This file will contain both certificate and private key.

**MASTER ** : Ip of master node in a scaled barbican cluster setup. Leave this field blank for a single server deplyment.

### Barbican service start/stop/restart

```
/opt/BarbiE/startup.sh start/stop/restart
```

## Testing Barbican SGX Integration

Go under /opt/BarbiE/test_scripts/

```
sudo python sgx.py <SPID> <CRT_PATH> <KDIR>
```

SPID     : SPID provided by IAS in hexstring format (hexstring as provided by Intel(R) during IAS registration process of client cert)
CRT_PATH : Absolute path of certificate for IAS server
KDIR     : Directory path to store client public private key pair

## Sample Commands

### SGX Aware client(without SGX Hardware) talking with Barbican Enclave 


ias_enable  | server_verify_ias | client_verify_ias | Expected output |
----------- | ----------------- | ----------------- |---------------- |
True        | True              | True              | Client verified quote |
True        | True              | False             | Server(E) verified quote |
True        | False             | True              | Client verified quote |
True        | False             | False             | Server(E) verified quote |
False       | True              | True              | Client verified quote |
False       | True              | False             | Server(E) not configured to do ias verification |
False       | False             | True              | Client verified quote |
False       | False             | False             | No IAS verification required. Fake report generated by server(E) |


**ias_enabled** flag represents if server configured to talk with IAS.

**server_verify_ias** flag is provided by client to let server do the quote verification with IAS.

**client_verify_ias** flag is provided by client to let server know that client will verify quote with IAS.


* #### Attestation and Secret management

```
sudo python sgx_client_wo_hw.py -ip [<IP>] -p <proj_id> -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias] -kdir /dirpath/to/store/keypair
```

    IP      : IPv4 address of the server.(Default - localhost)
    proj_id : Project ID
    client_verify_ias : Client will call IAS for quote verification.
    server_verify_ias : Server will call IAS for quote verification.
    SPID    : SPID provided by IAS in hexstring format. Required only when we are providing 'client_verify_ias'
    IAS_CRT : Absolute path of certificate for IAS server. Required only when we are providing 'client_verify_ias'
    kdir : Directory path to store client key pair

 #### Policy Management

```
sudo python project_policy_mgmt.py -ip [<IP>] -p <proj_id> -po [<policy>] -att [<attribute>]
```

    IP        : IPv4 address of the server. Default :- localhost
    proj_id   : Project ID
    policy    : Project Policy to be set.
                Accepted values :-
                1 :- Mr Signer of the Client is validated.
                2 :- Mr Enclave of the Client is validated.
                3 :- Mr Enclave of the Client is validated with a list of third party enclaves.
    attribute : Path of the file containing base64 encoded Mr Enclave or Mr Signer or list of Mr Enclave. First line of file will contain owner's Mr enclave.
    * **NOTE** owner is that enclave who created the project *

###  SGX Aware client with SGX Hardware

**E1** :- Enclave 1

**E2** :- Enclave 2(BarbiE)

**E1 is initiator of the Mutual Attestation with E2**


ias_enable  | server_verify_ias | client_verify_ias | Expected output |
----------- | ----------------- | ----------------- |---------------- |
True        | True              | True              | E1 & E2 verify quote when acting as client enclave |
True        | True              | False             | E1 & E2 verify quote when acting as server enclave |
True        | False             | True              | E1 & E2 verify quote when acting as client enclave|
True        | False             | False             | E1 & E2 verify quote when acting as server enclave |
False       | True              | True              | Server not configured to do ias verification |
False       | True              | False             | Server not configured to do ias verification |
False       | False             | True              | Server not configured to do ias verification |
False       | False             | False             | E1 verify quote when acting as server enclave & E2 generate fake report when acting as server |


**ias_enabled** flag represents if server configured to talk with IAS.

**server_verify_ias** flag is provided by client to let server do the quote verification with IAS.

**client_verify_ias** flag is provided by client to let server know that client will verify quote with IAS.


* #### Mutual Attestation and Secret Management

```
  sudo python sgx_client_with_hw.py -ip [<IP>] -p <proj_id> -po [<policy>] -mre [<mr_enclave_list_file_path>] -s [<SPID>] -crt [<IAS_CRT>] [--server_verify_ias] [--client_verify_ias] -o_mr_e [<owner_mr_enclave>] -kdir /dirpath/to/store/keypair
```

        IP      : IPv4 address of the server. Default :- localhost
        proj_id : Project ID
        client_verify_ias : Client will call IAS for quote verification.
        server_verify_ias : Server will call IAS for quote verification.
        SPID    : SPID provided by IAS in hex string format
        IAS_CRT : Absolute path of certificate for IAS server. This file will contain both certificate and private key. Required only when we are providing 'client_verify_ias'
        owner_mr_enclave  : Mr enclave of that enclave who created the project.
        kdir    : Directory path to store generated key pair

* #### Policy Management

```
sudo python project_policy_mgmt.py -ip [<IP>] -p <proj_id> -po [<policy>] -att [<attribute>]
```

    IP        : IPv4 address of the server. Default :- localhost
    proj_id   : Project ID
    policy    : Project Policy to be set.
                Accepted values :-
                1 :- Mr Signer of the Client is validated.
                2 :- Mr Enclave of the Client is validated.
                3 :- Mr Enclave of the Client is validated with a list of third party enclaves.
    attribute : Path of the file containing base64 encoded Mr Enclave or Mr Signer or list of Mr Enclave. First line of file will contain owner's Mr enclave.
    * **NOTE** owner is that enclave who created the project *

* #### Example sequence of steps for secure key management

1. While testing clients with enclaves, get the MR_ENCLAVE value of you client enclave. If hex encoded, then convert the hex encoded mr_enclave value to base64 format

```
echo “hex encoded mr_enclave string” | xxd –r –p | base64
```
    
This will print the base64 string of the mr_enclave. Copy it

2. Go inside /opt/barbiE/test_scripts folder. Execute the client enclave to test secret management on a fresh new project ID. Pass the base64 string of mr_enclave as the owner of the project.

```
python sgx_client_with_hw.py -ip 127.0.0.1 -p <new_project_id> -s 89938EF55B8EB8501972C5C1B76DC8C8 -crt /opt/BarbiE/client.pem --server_verify_ias  -o_mr_e  <base64_string of the owner’s mrenclave>  -kdir ./
```

3. If you want give other enclaves access to the secrets of this project then create a file with any name and copy the base64 string of owner enclave as the first line and then base64 string of mr_enclave or mr_signer of other enclave who can access the secret. 

Example content of the file containing list of identities

```
yy0Q5ER3pwI+r50fVLoS2AjkPKzzTYi5qMx555NcYIU=
YCd60v38V+mA6Hbn+HisGQmIDqU4B5Wn6OqYsVeEH4U= 
```

4. Save the file and issue the policy management command to set the policy for third party mr_enclave verification

```
python project_policy_mgmt.py -ip 127.0.0.1 -p <same project id as above>  -po 3 -att <file containing list of mr_enclave base64 values. First line should always be owner’s mr_enclave base64 value>
```

5. Or issue the policy management command to set the policy for third party mr_signer verification only.

```
python project_policy_mgmt.py -ip 127.0.0.1 -p <same project id as above> -po 2 -att <file containing just the mr_signer base64 value in the second line. First line should be owner’s mr_enclave base64 value>
```
 

```diff
- The above test scripts are for standalone use of barbican. If barbican is configured with Keystone, the client scripts wont work.
```

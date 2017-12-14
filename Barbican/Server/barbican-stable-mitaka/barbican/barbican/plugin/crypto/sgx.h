#define SGX_ECP256_KEY_SIZE	32

typedef uint64_t sgx_enclave_id_t;
// Enum for all possible message types between the ISV app and
// the ISV SP. Requests and responses in hte remote attestation
// sample.
typedef enum _ra_msg_type_t
{
     TYPE_RA_MSG1 = 1,
     TYPE_RA_MSG2,
     TYPE_RA_MSG3,
     TYPE_RA_ATT_RESULT,
}ra_msg_type_t;

// Enum for all possible message types between the SP and IAS.
// Network communication is not simulated in the remote
// attestation sample.  Currently these aren't used.
typedef enum _ias_msg_type_t
{
     TYPE_IAS_ENROLL,
     TYPE_IAS_GET_SIGRL,
     TYPE_IAS_SIGRL,
     TYPE_IAS_ATT_EVIDENCE,
     TYPE_IAS_ATT_RESULT,
}ias_msg_type_t;

typedef struct _ra_samp_msg0_request_header_t{
    uint8_t type;  // set to one of ra_msg_type_t
    uint32_t size; //size of request body,
    uint8_t align[3];
    uint8_t body[36];
}ra_samp_msg0_request_header_t;

typedef struct _ra_samp_msg1_request_header_t{
    uint8_t type;  // set to one of ra_msg_type_t
    uint32_t size; //size of request body,
    uint8_t align[3];
    uint8_t body[68];
}ra_samp_msg1_request_header_t;

typedef struct _ra_samp_msg3_request_header_t{
    uint8_t type;  // set to one of ra_msg_type_t
    uint32_t size; //size of request body,
    uint8_t align[3];
    uint8_t body[1452];
}ra_samp_msg3_request_header_t;

typedef struct _ra_samp_msg1_response_header_t{
    uint8_t type;   // set to one of ra_msg_type_t
    uint8_t status[2];
    uint32_t size;  //size of the response body
    uint8_t align[1];
    uint8_t body[168];
}ra_samp_msg1_response_header_t;

typedef struct _ra_samp_msg3_response_header_t{
    uint8_t type;   // set to one of ra_msg_type_t
    uint8_t status[2];
    uint32_t size;  //size of the response body
    uint8_t align[1];
    uint8_t body[145];
}ra_samp_msg3_response_header_t;

typedef struct sgx_ec256_public_t
{
    uint8_t gx[SGX_ECP256_KEY_SIZE];
    uint8_t gy[SGX_ECP256_KEY_SIZE];
}sgx_ec256_public_t;

typedef struct sgx_ec256_private_t
{
    uint8_t r[SGX_ECP256_KEY_SIZE];
}sgx_ec256_private_t;

typedef uint32_t sgx_ra_context_t;

/*
*   Create the Barbican enclave (BarbiE).
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*/
int initialize_enclave(sgx_enclave_id_t *enclave_id);
/*
*   Destroy the Barbican enclave.
*/
void destroy_enclave(sgx_enclave_id_t enclave_id);
/*
*   Generate a 16 byte key, returned in sealed form.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [2] sealed_key_len - seal buffer len for a 16 byte key
*   Output: [1] sealed_key - sealed_key_len byte buffer to store sealed key material
*/
int crypto_generate_key(sgx_enclave_id_t enclave_id, size_t key_len, uint8_t *sealed_key, size_t sealed_key_len);
/*
*   Compare 2 buffers.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on same.
*   Inputs: [1] buf1
*           [2] buf2
*           [3] len
*/
int crypto_cmp(uint8_t *buf1, uint8_t *buf2, size_t len);
/*
*   Securely compare 2 sealed keys.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on same plain text recovered.
*   Inputs: [1] sealed_key1
*           [2] sealed_len1
*           [3] sealed_key2
*           [4] sealed_len2
*/
int crypto_sealed_cmp(sgx_enclave_id_t enclave_id, uint8_t *sealed_key1, size_t sealed_len1, uint8_t *sealed_key2, size_t sealed_len2);
/*
*   Securely encrypt contents of sealed buffer with with key material retrieved from another sealed buffer.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] sealed_key - key used to generate enc_secret.
*           [2] sealed_key_len
*           [3] sealed_secret - secret to transport.
*           [4] sealed_secret_len
*   Output:
*           [5] enc_secret - plain text recovered from sealed_secret encrypted with key retrieved from sealed_key.
*           [6] enc_secret_len
*           [7] secret_iv
*           [8] secret_mac
*           [9] project_id - aad for encrypt sk
*           [10] project_id_len.
*/
int crypto_transport_secret(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, uint8_t *sealed_secret, size_t sealed_secret_len, uint8_t *enc_secret, size_t enc_secret_len, uint8_t *secret_iv, uint8_t *secret_mac, uint8_t *project_id, size_t project_id_len);
/*
*   Securely encrypt plain text with with key material retrieved from sealed key.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] sealed_key - key used to generate cypher_text.
*           [2] sealed_len
*           [3] plain_text - buffer to be encrypted.
*           [4] plain_text_len
*   Output:
*           [5] cypher_text
*           [6] iv
*           [7] mac
*/
int crypto_encrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac);
int crypto_legacy_encrypt(uint8_t *key, size_t key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac);
/*
*   Securely decrypt cypher text with with key material retrieved from sealed key.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] sealed_key - key used to generate cypher_text.
*           [2] sealed_len
*           [4] plain_text_len
*           [5] cypher_text - buffer to be decryped.
*           [6] iv
*           [7] mac
*   Output:
*           [3] plain_text
*/
int crypto_decrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_key, size_t sealed_key_len, char *plain_text, size_t plain_text_len, uint8_t *cypher_text, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len);
/*
*   Securely decrypt user symmetric key (SK) encrypted secret and encrypt with key encryption key (KEK) retreived from sealed kek blob.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] kek_enc_sk - SK encrypted with KEK.
*           [2] kek_enc_sk_len
*           [3] sk_iv
*           [4] sk_mac
*           [5] sealed_kek
*           [6] sealed_kek_len
*           [7] sk_enc_secret
*           [8] sk_enc_secret_len
*           [10] kek_enc_secret_len
*           [11] iv
*           [12] mac
*           [13] project_id - aad for decrypt sk
*           [14] project_id_len
*   Output:
*           [9] kek_enc_secret
*           [11] iv
*           [12] mac
*/
int crypto_store_secret(sgx_enclave_id_t enclave_id, uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id,size_t project_id_len);
/*
*   Securely decrypt user key encryption key (KEK) encrypted secret and encrypt with symmetric key (SK).
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] kek_enc_sk - SK encrypted with KEK.
*           [2] kek_enc_sk_len
*           [3] sk_iv
*           [4] sk_mac
*           [5] sealed_kek
*           [6] sealed_kek_len
*           [7] kek_enc_secret
*           [8] kek_enc_secret_len
*           [10] sk_enc_secret_len
*           [11] iv
*           [12] mac
*           [13] project_id - aad for decrypt sk
*           [14] project_id_len
*   Output:
*           [9] sk_enc_secret
*           [11] iv
*           [12] mac
*/
int crypto_get_secret(sgx_enclave_id_t enclave_id, uint8_t *kek_enc_sk, size_t kek_enc_sk_len, uint8_t *sk_iv, uint8_t *sk_mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *kek_enc_secret, size_t kek_enc_secret_len, uint8_t *sk_enc_secret, size_t sk_enc_secret_len, uint8_t *iv, uint8_t *mac, uint8_t *project_id, size_t project_id_len);
/*
*   Initilizes an RA session returning RA context for future RA calls associated with this challenge and msg1 to send to challenger.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: 
*   Output: [1] context - RA session handle.
*           [2] p_msg1_full - msg1 header and body.
*/
int gen_msg0(ra_samp_msg0_request_header_t **pp_msg0_full, uint8_t *spid);
int proc_msg0(ra_samp_msg0_request_header_t *p_msg_full, void **pp_ra_ctx, uint8_t *spid, bool client_verify_ias);
int gen_msg1(sgx_enclave_id_t enclave_id, sgx_ra_context_t *context, ra_samp_msg1_request_header_t **pp_msg1_full, char *pub_key);
int gen_msg3(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg1_response_header_t *p_msg2_full, ra_samp_msg3_request_header_t** pp_msg3_full, uint8_t *ias_crt, bool client_verify_ias, bool server_verify_ias, uint8_t *resp_crt, uint8_t *resp_sign, uint8_t *resp_body);
int proc_msg3(ra_samp_msg3_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_msg3_response_header_t **pp_msg_resp_full, ra_samp_msg3_request_header_t *p_msg_full, uint8_t *project_id, uint8_t *owner_mr_e, uint8_t *ias_crt, bool client_verify_ias);
int get_mk_mr_list(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, uint8_t *sk_mr_list, size_t sk_mr_list_len, uint8_t *project_id, size_t project_id_len, uint8_t *mk_mr_list, size_t mk_mr_list_len, uint8_t *new_mk_mr_list, uint8_t *iv1, uint8_t *mac1, uint8_t *iv2, uint8_t *mac2, uint8_t *iv3, uint8_t *mac3, uint8_t *iv, uint8_t *mac);
int get_sk_data(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, uint8_t *mk_data, size_t mk_data_len, uint8_t *project_id, size_t project_id_len, uint8_t *sk_data, uint8_t *iv1, uint8_t *mac1, uint8_t *iv2, uint8_t *mac2, uint8_t *iv, uint8_t *mac);
/*
*   Processes RA msg2 and if successful generates msg3.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] context - RA ession handle.
*           [2] p_msg2_full - msg2 header and body.
*   Output: [3] p_msg3_full - msg3 header and body.
*/
int proc_msg1(ra_samp_msg1_request_header_t *p_msg_full, void **pp_ra_ctx, ra_samp_msg1_response_header_t **pp_msg_resp_full, sgx_ec256_private_t* priv_key);
/*
*   Processes RA msg4 (attestation result) and if successful extracts secret being provisioned.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [2] sealed_len
*           [3] p_att_result_msg_full - msg4 header and body.
*   Output: [1] sealed_secret - provisioned secret in sealed form.
*/
int proc_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_secret, size_t sealed_len, uint8_t *sealed_secret2, size_t secret2_len);

int ma_proc_ra(sgx_enclave_id_t enclave_id, ra_samp_msg3_response_header_t* s_msg4, sgx_ra_context_t s_p_ctxt, ra_samp_msg3_request_header_t* c_msg3, void **c_p_net_ctxt, ra_samp_msg3_response_header_t **pp_resp2, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *ias_crt, bool client_verify_ias, int policy, uint8_t *attribute, size_t attribute_len, uint8_t *iv1, uint8_t *mac1);
int new_proc_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *dh_sk, size_t dk_sk_len, uint8_t *iv1, uint8_t *mac1);
/*
*   Close RA session using handle.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] context
*   Output:
*/
int close_ra(sgx_enclave_id_t enclave_id, sgx_ra_context_t context);
/*
*   Securely recover KEK from SK encrypted KEK and returns sealed form.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] sealed_sk
*           [2] sealed_sk_len
*           [3] sk_enc_kek - KEK encrypted with SK.
*           [4] sk_enc_kek_len
*           [5] iv
*           [6] mac
*           [8] sealed_kek_len
*   Output:
*           [7] sealed_kek
*/
int crypto_provision_kek(sgx_enclave_id_t enclave_id, uint8_t *sealed_sk, size_t sealed_sk_len, uint8_t *sk_enc_kek, size_t sk_enc_kek_len, uint8_t *iv, uint8_t *mac, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *project_id, size_t project_id_len);

int get_kek(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *sk_kek, size_t sk_kek_len, uint8_t *iv1, uint8_t *mac1, uint8_t *sealed_kek, size_t sealed_kek_len, uint8_t *project_id, size_t project_id_len);
int secret_encrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *sk_secret, size_t sk_secret_len, uint8_t *iv1, uint8_t *mac1, uint8_t *mk_secret, size_t plain_sk_len, uint8_t *iv2, uint8_t *mac2, uint8_t *project_id, size_t project_id_len);
int secret_decrypt(sgx_enclave_id_t enclave_id, uint8_t *sealed_mk, size_t sealed_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, uint8_t *mk_secret, size_t mk_secret_len, uint8_t *iv1, uint8_t *mac1, uint8_t *sk_secret, size_t plain_sk_len, uint8_t *iv2, uint8_t *mac2, uint8_t *project_id, size_t project_id_len);

int set_enclave(void **pp_ra_ctx, sgx_enclave_id_t enclave_id);
int set_secret(void **pp_ra_ctx, uint8_t *secret, size_t secret_len, uint8_t *secret2, size_t secret2_len);

size_t get_sealed_data_len(sgx_enclave_id_t enclave_id, size_t add, size_t plain_len);
size_t get_add_mac_len(sgx_enclave_id_t enclave_id, uint8_t* sealed_buf_ptr, uint32_t sealed_len);
size_t get_encrypted_len(sgx_enclave_id_t enclave_id, uint8_t* sealed_buf_ptr, uint32_t sealed_len);
int get_sk(void **pp_ra_ctx, uint8_t *plain_sk, size_t sk_len, uint8_t *enc_sk, uint8_t *sk_iv, uint8_t *sk_mac);
int get_dh_key(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *sealed_secret, size_t sealed_len);
/*
*   Getting project id length from msg4.
* Parameters:
*   Return: size_t project_id_len.
*   Inputs: [1] context
*           [2] p_att_result_msg_full - msg4 header and body.
*/
int get_project_id_len(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full);
/*
*   Getting project id from msg4.
* Parameters:
*   Return: sgx_status_t - SGX_SUCCESS on success, error code otherwise.
*   Inputs: [1] context
*           [2] p_att_result_msg_full - msg4 header and body
*   Output:
*           [3] project_id
*/
int get_project_id(sgx_enclave_id_t enclave_id, sgx_ra_context_t context, ra_samp_msg3_response_header_t* p_att_result_msg_full, uint8_t *project_id);
uint8_t *get_mr_e(ra_samp_msg3_request_header_t *p_msg3);
uint8_t *get_mr_s(ra_samp_msg3_request_header_t *p_msg3);
int get_report_sha256(ra_samp_msg3_request_header_t *p_msg3, uint8_t *sha256);

/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <assert.h>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "remote_attestation_result.h"
#include <stdarg.h>
#include <stdio.h>     /* vsnprintf */
#include <stdlib.h>

#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "sgx_quote.h"
#include "sgx_key_exchange.h"
#include "sgx_eid.h"

#include <string.h>    // memcpy
#include "seal.h"
#define IV_SIZE 12
#define SK_KEY_SIZE 16

#ifndef SAMPLE_FEBITSIZE
    #define SAMPLE_FEBITSIZE                    256
#endif

#define SAMPLE_ECP_KEY_SIZE                     (SAMPLE_FEBITSIZE/8)

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

 typedef struct sample_ec_pub_t
{
    uint8_t gx[SAMPLE_ECP_KEY_SIZE];
    uint8_t gy[SAMPLE_ECP_KEY_SIZE];
} sample_ec_pub_t;

typedef struct sample_ec_priv_t
{
    uint8_t r[SAMPLE_ECP_KEY_SIZE];
} sample_ec_priv_t;

typedef uint8_t sample_ec_key_128bit_t[16];

typedef struct sample_ps_sec_prop_desc_t
{
    uint8_t  sample_ps_sec_prop_desc[256];
} sample_ps_sec_prop_desc_t;

typedef struct _sp_db_item_t
{
    sample_ec_pub_t             g_a;
    sample_ec_pub_t             g_b;
    sample_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
    sample_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
    sample_ec_key_128bit_t      sk_key;// Shared secret key for encryption
    sample_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
    sample_ec_priv_t            b;
    sample_ps_sec_prop_desc_t   ps_sec_prop;
    // TODO, less than ideal but leveraging this structure as it has to be passed
    sgx_enclave_id_t            enclave_id;
    size_t                      secret_len;
    uint8_t                     *secret;
    size_t                      secret2_len;
    uint8_t                     *secret2;
}sp_db_item_t;

void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

// This is the public EC key of the SP. The corresponding private EC key is
// used by the SP to sign data used in the remote attestation SIGMA protocol
// to sign channel binding data in MSG2. A successful verification of the
// signature confirms the identity of the SP to the ISV app in remote
// attestation secure channel binding. The public EC key should be hardcoded in
// the enclave or delivered in a trustworthy manner. The use of a spoofed public
// EC key in the remote attestation with secure channel binding session may lead
// to a security compromise. Every different SP the enlcave communicates to
// must have a unique SP public key. Delivery of the SP public key is
// determined by the ISV. The TKE SIGMA protocl expects an Elliptical Curve key
// based on NIST P-256
static const sgx_ec256_public_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

// Used to store the secret passed by the SP in the sample code. The
// size is forced to be 8 bytes. Expected value is
// 0x01,0x02,0x03,0x04,0x0x5,0x0x6,0x0x7
uint8_t g_secret[8] = {0};


#ifdef SUPPLIED_KEY_DERIVATION

#pragma message ("Supplied key derivation function is used.")

typedef struct _hash_buffer_t
{
    uint8_t counter[4];
    sgx_ec256_dh_shared_t shared_secret;
    uint8_t algorithm_id[4];
} hash_buffer_t;

const char ID_U[] = "SGXRAENCLAVE";
const char ID_V[] = "SGXRASERVER";

// Derive two keys from shared key and key id.
bool derive_key(
    const sgx_ec256_dh_shared_t *p_shared_key,
    uint8_t key_id,
    sgx_ec_key_128bit_t *first_derived_key,
    sgx_ec_key_128bit_t *second_derived_key)
{
    sgx_status_t sgx_ret = SGX_SUCCESS;
    hash_buffer_t hash_buffer;
    sgx_sha_state_handle_t sha_context;
    sgx_sha256_hash_t key_material;

    memset(&hash_buffer, 0, sizeof(hash_buffer_t));
    /* counter in big endian  */
    hash_buffer.counter[3] = key_id;

    /*convert from little endian to big endian */
    for (size_t i = 0; i < sizeof(sgx_ec256_dh_shared_t); i++)
    {
        hash_buffer.shared_secret.s[i] = p_shared_key->s[sizeof(p_shared_key->s)-1 - i];
    }

    sgx_ret = sgx_sha256_init(&sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&hash_buffer, sizeof(hash_buffer_t), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_U, sizeof(ID_U), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_update((uint8_t*)&ID_V, sizeof(ID_V), sha_context);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_get_hash(sha_context, &key_material);
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha256_close(sha_context);
        return false;
    }
    sgx_ret = sgx_sha256_close(sha_context);

    assert(sizeof(sgx_ec_key_128bit_t)* 2 == sizeof(sgx_sha256_hash_t));
    memcpy(first_derived_key, &key_material, sizeof(sgx_ec_key_128bit_t));
    memcpy(second_derived_key, (uint8_t*)&key_material + sizeof(sgx_ec_key_128bit_t), sizeof(sgx_ec_key_128bit_t));

    // memset here can be optimized away by compiler, so please use memset_s on
    // windows for production code and similar functions on other OSes.
    memset(&key_material, 0, sizeof(sgx_sha256_hash_t));

    return true;
}

//isv defined key derivation function id
#define ISV_KDF_ID 2

typedef enum _derive_key_type_t
{
    DERIVE_KEY_SMK_SK = 0,
    DERIVE_KEY_MK_VK,
} derive_key_type_t;

sgx_status_t key_derivation(const sgx_ec256_dh_shared_t* shared_key,
    uint16_t kdf_id,
    sgx_ec_key_128bit_t* smk_key,
    sgx_ec_key_128bit_t* sk_key,
    sgx_ec_key_128bit_t* mk_key,
    sgx_ec_key_128bit_t* vk_key)
{
    bool derive_ret = false;

    if (NULL == shared_key)
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (ISV_KDF_ID != kdf_id)
    {
        //fprintf(stderr, "\nError, key derivation id mismatch in [%s].", __FUNCTION__);
        return SGX_ERROR_KDF_MISMATCH;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_SMK_SK,
        smk_key, sk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }

    derive_ret = derive_key(shared_key, DERIVE_KEY_MK_VK,
        mk_key, vk_key);
    if (derive_ret != true)
    {
        //fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
#else
#pragma message ("Default key derivation function is used.")
#endif

// This ecall is a wrapper of sgx_ra_init to create the trusted
// KE exchange key context needed for the remote attestation
// SIGMA API's. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
// @param b_pse Indicates whether the ISV app is using the
//              platform services.
// @param p_context Pointer to the location where the returned
//                  key context is to be copied.
//
// @return Any error return from the create PSE session if b_pse
//         is true.
// @return Any error returned from the trusted key exchange API
//         for creating a key context.

sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context,
    sgx_ec256_public_t *pub_key)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    if(b_pse)
    {
        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        if (ret != SGX_SUCCESS)
            return ret;
    }
#ifdef SUPPLIED_KEY_DERIVATION
    ret = sgx_ra_init_ex(pub_key, b_pse, key_derivation, p_context);
#else
    ret = sgx_ra_init(pub_key, b_pse, p_context);
#endif
    if(b_pse)
    {
        sgx_close_pse_session();
        return ret;
    }
    return ret;
}


// Closes the tKE key context used during the SIGMA key
// exchange.
//
// @param context The trusted KE library key context.
//
// @return Return value from the key context close API

sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}


// Verify the mac sent in att_result_msg from the SP using the
// MK key. Input pointers aren't checked since the trusted stubs
// copy them into EPC memory.
//
//
// @param context The trusted KE library key context.
// @param p_message Pointer to the message used to produce MAC
// @param message_size Size in bytes of the message.
// @param p_mac Pointer to the MAC to compare to.
// @param mac_size Size in bytes of the MAC
//
// @return SGX_ERROR_INVALID_PARAMETER - MAC size is incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESCMAC function.
// @return SGX_ERROR_MAC_MISMATCH - MAC compare fails.

sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}


// Generate a secret information for the SP encrypted with SK.
// Input pointers aren't checked since the trusted stubs copy
// them into EPC memory.
//
// @param context The trusted KE library key context.
// @param p_secret Message containing the secret.
// @param secret_size Size in bytes of the secret message.
// @param p_gcm_mac The pointer the the AESGCM MAC for the
//                 message.
//
// @return SGX_ERROR_INVALID_PARAMETER - secret size if
//         incorrect.
// @return Any error produced by tKE  API to get SK key.
// @return Any error produced by the AESGCM function.
// @return SGX_ERROR_UNEXPECTED - the secret doesn't match the
//         expected value.

sgx_status_t client_put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac, uint8_t *sealed_buf, size_t sealed_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    sgx_ec_key_128bit_t secret;

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }

        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         (uint8_t *) &secret,
                                         &aes_gcm_iv[0],
                                         IV_SIZE,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)
                                            (p_gcm_mac));
        if(SGX_SUCCESS != ret)
        {
            printf("\nclient_put_secret_data failed\n");
            break;
        }
        
        ret = (sgx_status_t) seal(sealed_buf, sealed_len, (uint8_t *) &secret, sizeof(sgx_ec_key_128bit_t));
    } while(0);
    return ret;
}

sgx_status_t server_get_project_id(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac, uint8_t *sealed_buf, size_t sealed_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    sgx_ec_key_128bit_t secret;
    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                         p_secret,
                                         secret_size,
                                         sealed_buf,
                                         &aes_gcm_iv[0],
                                         IV_SIZE,
                                         NULL,
                                         0,
                                         (const sgx_aes_gcm_128bit_tag_t *)
                                            (p_gcm_mac));
        if(SGX_SUCCESS != ret)
        {
            break;
        }

    } while(0);
    return ret;
}

sgx_status_t ecall_get_ra_dh_key(
    sgx_ra_context_t context,
    uint8_t *sealed_buf, size_t sealed_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;

    do {
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }

        ret = (sgx_status_t) seal(sealed_buf, sealed_len, (uint8_t *) &sk_key, sizeof(sgx_ec_key_128bit_t));
    } while(0);
    return ret;
}

sgx_status_t ecall_get_mr_enclave(
    sgx_ra_context_t context,
    uint8_t *mr_enclave, size_t mr_e_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_report_t *report = (sgx_report_t *) malloc(sizeof(sgx_report_t));

    ret = sgx_create_report(NULL, NULL, report);
    if(SGX_SUCCESS != ret)
    {
        printf("Error retrieving report data for extracting mr enclave");
    }
    else
    {
        memcpy(mr_enclave, report->body.mr_enclave.m, 32);
    }
    free(report);
    return ret;
}

void server_put_secret_data(uint8_t *sealed_sk, size_t sealed_len, uint8_t *plain_ra_key, size_t plain_ra_key_len, uint8_t *ra_key_enc_sk, uint8_t *iv, uint8_t *mac)
{
    if (!sealed_sk || !plain_ra_key || !ra_key_enc_sk || !iv || !mac) return;
	sgx_status_t status = SGX_SUCCESS;
	sgx_key_128bit_t tmp_key;
	unseal(sealed_sk, sealed_len, (uint8_t *) &tmp_key, sealed_len - sizeof(sgx_sealed_data_t));
	status = sgx_rijndael128GCM_encrypt((sgx_key_128bit_t *) plain_ra_key,
            tmp_key, sealed_len - sizeof(sgx_sealed_data_t), ra_key_enc_sk, iv, IV_SIZE, NULL, 0, reinterpret_cast<uint8_t (*)[16]>(mac));
	if(SGX_SUCCESS != status)
	{
		printf("Error encrypting plain text\n");
	}
    memset_s(&tmp_key, sizeof(tmp_key), 0, sizeof(tmp_key));
}

bool is_trusted_enclave(uint8_t *mr_list, size_t mr_list_len,  uint8_t *client_mr_e)
{

    if(client_mr_e == NULL)
    {
        return NULL;
    }

    int total_mr_e =  mr_list_len/32;
    int n = 0;
    for(int i =0; i < total_mr_e; i++)
    {
        if(memcmp(mr_list + n, client_mr_e, 32) == 0)
        {
            return true;
        }
        n = n + 32;
    }
    return false;
}

uint8_t *ecall_sp_get_mr_e(sgx_quote_t *p_quote)
{
    sgx_status_t ret = SGX_SUCCESS;
    if(!p_quote)
    {
        return NULL;
    }
    return p_quote->report_body.mr_enclave.m;
}

uint8_t *ecall_sp_get_mr_s(sgx_quote_t *p_quote)
{
    sgx_status_t ret = SGX_SUCCESS;
    if(!p_quote)
    {
        return NULL;
    }
    return p_quote->report_body.mr_signer.m;
}

int ecall_proc_ma(sample_ra_att_result_msg_t *s_msg4_body, size_t s_msg4_body_len, sgx_ra_context_t s_p_ctxt, sgx_quote_t *c_msg3_p_quote, size_t c_msg3_p_quote_len, void **c_p_net_ctxt, uint8_t *sealed_mk, size_t sealed_mk_len, uint8_t *mk_sk, size_t mk_sk_len, uint8_t *iv, uint8_t *mac, int policy, uint8_t *attribute, size_t attribute_len, uint8_t *iv1, uint8_t *mac1, sample_ra_att_result_msg_t *c_msg4_body, size_t c_msg4_body_len, uint8_t *project_id, size_t project_id_len)
{
    sgx_status_t ret = SGX_SUCCESS;
    sp_db_item_t *sp_db = NULL;
    size_t sealed_sk_len = ecall_get_sealed_data_len(0, 16);
    uint8_t *sealed_sk = (uint8_t *) malloc(sealed_sk_len);
    uint8_t *sealed_nonse = (uint8_t *) malloc(sealed_sk_len);
    uint8_t *mr_to_verify = NULL;
    uint8_t *r_client_mr_e = s_msg4_body->data1.payload;
    uint8_t *r_server_mr_e = s_msg4_body->data2.payload;
    uint8_t *r_owner_mr_e = s_msg4_body->data3.payload;
    //client and server mr enclave extracted here

    uint8_t *client_mr_e = ecall_sp_get_mr_e(c_msg3_p_quote);
    uint8_t *client_mr_s = ecall_sp_get_mr_s(c_msg3_p_quote);
    uint8_t *server_mr_e = (uint8_t *) malloc(32);
    ecall_get_mr_enclave(s_p_ctxt, server_mr_e, 32);

    //verifying policy for client
    if(policy == 2)
    {
       //going to verify mr signer of client
       mr_to_verify = client_mr_s;
    }
    else if (policy == 1 || policy == 3)
    {
       //going to verify mr enclave of client
       mr_to_verify = client_mr_e;
    }
    if(memcmp(client_mr_e, r_client_mr_e, 32) == 0 && memcmp(server_mr_e, r_server_mr_e, 32) ==0)
    {
        if(memcmp(r_client_mr_e, r_owner_mr_e, 32) == 0 && strlen((char *)sealed_mk) == 0 && strlen((char *)mk_sk) == 0)
        {
            printf("\nGenerate new keys\n");
            ret = ecall_generate_key(SK_KEY_SIZE, sealed_sk, sealed_sk_len);
            sealed_mk_len = sealed_sk_len;
            uint8_t *tmp_sealed_mk = NULL;
            tmp_sealed_mk = (uint8_t *) malloc(sealed_mk_len);
            ret = ecall_generate_key(SK_KEY_SIZE, tmp_sealed_mk, sealed_mk_len);
            memcpy(sealed_mk, tmp_sealed_mk, sealed_mk_len);
            memset_s(tmp_sealed_mk, sealed_mk_len, 0, sealed_mk_len);
            free(tmp_sealed_mk);
            tmp_sealed_mk = NULL;
            if(ret != SGX_SUCCESS)
            {
                 printf("\nError in generating sealed master key");
            }

            ecall_transport_secret(sealed_mk, sealed_mk_len, sealed_sk, sealed_sk_len, mk_sk, SK_KEY_SIZE, iv, mac, project_id, project_id_len);
        }
        else
        {
            if(policy == 0)
            {
                 printf("\nPolicy not set");
                 return 5;
            }
            ecall_provision_kek(sealed_mk, sealed_mk_len, mk_sk, mk_sk_len, iv, mac, sealed_sk, sealed_sk_len, project_id, project_id_len);
            printf( "\nUse existing keys");
            uint8_t *mr_list = (uint8_t *)malloc(attribute_len);
            ecall_decrypt(sealed_mk, sealed_mk_len, mr_list, attribute_len, attribute, iv1, mac1, sealed_sk, sealed_sk_len);
            //compare r_owner_mr_e with first entry in mr_list
            if(memcmp(mr_list, r_owner_mr_e, 32) ==0){
                if(!is_trusted_enclave(mr_list, attribute_len, mr_to_verify))
                {
                    printf("\n******************* Untrusted Enclave **********\n");
                    free(mr_list);
                    return 1;
                }
            }
            else
            {
                printf("\n******************* Owner in Mr List provided does not match with the given owner **********\n");
                free(mr_list);
                return 2;
            }
        }
    }
    else
    {
        printf("\nEnclave Identity verification failed\n");
        return 3;
    }
    ret = client_put_secret_data(s_p_ctxt,
                                 s_msg4_body->secret.payload,
                                 s_msg4_body->secret.payload_size,
                                 s_msg4_body->secret.payload_tag,
                                 sealed_nonse, sealed_sk_len);

    if(SGX_SUCCESS != ret) {
        printf("\nError in retrieving sealed nonse from msg4\n");
        return 4;
    }

    sp_db = (sp_db_item_t *)*c_p_net_ctxt;
    uint8_t aes_gcm_iv[12] = {0};

    c_msg4_body->secret.payload_size = ecall_get_encrypt_txt_len(sealed_nonse, sealed_sk_len);
      server_put_secret_data(sealed_nonse, sealed_sk_len, (uint8_t *) &sp_db->sk_key, sizeof(sp_db->sk_key),
        (uint8_t *) c_msg4_body->secret.payload, &aes_gcm_iv[0], (uint8_t *) &c_msg4_body->secret.payload_tag); 

    c_msg4_body->data1.payload_size = ecall_get_encrypt_txt_len(sealed_sk, sealed_sk_len);
    server_put_secret_data(sealed_sk, sealed_sk_len, (uint8_t *) &sp_db->sk_key, sizeof(sp_db->sk_key),
    (uint8_t *) c_msg4_body->data1.payload, &aes_gcm_iv[0], (uint8_t *) &c_msg4_body->data1.payload_tag);


    free(sealed_sk);
	sealed_sk = NULL;
    free(sealed_nonse);
	sealed_nonse = NULL;
    free(server_mr_e);
	server_mr_e = NULL;
    return 0;
}

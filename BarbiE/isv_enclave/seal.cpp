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
//#include "sgx_tkey_exchange.h"
//#include "sgx_tcrypto.h"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "sgx_tseal.h"
//#include "sgx_tcrypto.h"
#include <string.h>    // memcpy
#include "seal.h"
errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if(numberOfElements<count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

int unseal(uint8_t *sealed_buf_ptr, uint32_t sealed_len, uint8_t *unsealed_buf_ptr, uint32_t unsealed_len)
{
	// TODO sgx_is_outside_enclave
    if(sealed_buf_ptr == NULL || unsealed_buf_ptr == NULL)
    {
        return -1;
    }

    uint32_t unsealed_data_length = unsealed_len;
    uint8_t *plain_text = NULL;
    uint32_t plain_text_length = 0;
//todo, not needed, all in enclave for now
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_len);
    if(temp_sealed_buf == NULL)
    {
        printf("Out of memory.\n");
        return -1;
    }

    memcpy_s(temp_sealed_buf, sealed_len, sealed_buf_ptr, sealed_len);

    // Unseal current sealed buf
    sgx_status_t ret = sgx_unseal_data((sgx_sealed_data_t *)temp_sealed_buf, plain_text, &plain_text_length, unsealed_buf_ptr, &unsealed_data_length);
    if(ret == SGX_SUCCESS)
    {
        free(temp_sealed_buf);
        return 0;
    }
    else
    {
        printf("Failed to reinitialize the enclave.\n");
        free(temp_sealed_buf);
        return -1;
    }
}

int seal(uint8_t *sealed_buf_ptr, uint32_t sealed_len, uint8_t * unsealed_buf_ptr, uint32_t unsealed_len)
{
	// TODO sgx_is_outside_enclave
    if(sealed_buf_ptr == NULL || unsealed_buf_ptr == NULL)
    {
        return -1;
    }

    uint8_t *plain_text = NULL;
    uint32_t plain_text_length = 0;
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_len);
    if(temp_sealed_buf == NULL)
    {
        printf("Out of memory.\n");
        return -1;
    }
    memset(temp_sealed_buf, 0, sealed_len);


    // Increase and seal the secret data
    sgx_status_t ret = sgx_seal_data(plain_text_length, plain_text, unsealed_len, unsealed_buf_ptr, sealed_len, (sgx_sealed_data_t *)temp_sealed_buf);
    if(ret != SGX_SUCCESS)
    {
        printf("Failed to seal data\n");
        free(temp_sealed_buf);
        return -1;
    }
    // Backup the sealed data to outside buffer
    memcpy_s(sealed_buf_ptr, sealed_len, temp_sealed_buf, sealed_len);

    free(temp_sealed_buf);

    // Ocall to print the unsealed secret data outside.
    // In theory, the secret data(s) SHOULD NOT be transferred outside the enclave as clear text(s).
    // So please DO NOT print any secret outside. Here printing the secret data to outside is only for demo.
    return 0;
}

size_t ecall_get_sealed_data_len(size_t add, size_t plain_len)
{
    return sgx_calc_sealed_data_size(add, plain_len);
}

size_t ecall_get_add_mac_len(uint8_t *sealed_buf_ptr, uint32_t sealed_len)
{
    return sgx_get_add_mac_txt_len((sgx_sealed_data_t*) sealed_buf_ptr);
}

size_t ecall_get_encrypt_txt_len(uint8_t *sealed_buf_ptr, uint32_t sealed_len)
{
    return sgx_get_encrypt_txt_len((sgx_sealed_data_t*) sealed_buf_ptr);
}

#pragma once

#define IV_SIZE                     12
#define CYPHER_TEXT_META_DATA_LEN   ((IV_SIZE) + (SGX_AESGCM_MAC_SIZE))
#define CALC_ENC_SIZE(y)            ((y) + (CYPHER_TEXT_META_DATA_LEN))
#define CALC_PLN_SIZE(y)            ((y) - (CYPHER_TEXT_META_DATA_LEN))
#define TO_SGX_CRYPTO               "/tmp/client_to_sgx_crypto_fifo"
#define FROM_SGX_CRYPTO             "/tmp/sgx_crypto_to_client_fifo"   
#define TO_SGX_STORE                "/tmp/client_to_sgx_store_fifo"
#define FROM_SGX_STORE              "/tmp/sgx_store_to_client_fifo"   
//#define myfifo                      "/tmp/client_to_server_fifo"
//#define myfifo2                     "/tmp/server_to_client_fifo"   

enum SGX_CRYPTO_API {
    CRYPTO_EXIT = -1,
    CRYPTO_SUPPORTS,
    CRYPTO_INITIALIZE,
    CRYPTO_ENCRYPT,
    CRYPTO_DECRYPT,
    CRYPTO_GEN_KEY,
    CRYPTO_INIT_RA,
    CRYPTO_PROC_MSG2_GEN_MSG3,
    CRYPTO_PROC_MSG4,
    CRYPTO_MAX
};

extern char *SGX_CRYPTO_API_STRS[CRYPTO_MAX + 1];

#define COMMAND_TO_STRING(command) (((command) < -1) || ((command) >= (CRYPTO_MAX))) ? "INVALID" : SGX_CRYPTO_API_STRS[(command) + 1]

size_t write_buffer(char *pbuf, size_t buf_len);
size_t read_buffer(char **ppbuf, size_t *pbuf_len);
size_t read_command(int *command);
size_t initialize_fifo(char *to_me, char *from_me);
void destroy_fifo(char *to_me, char *from_me);

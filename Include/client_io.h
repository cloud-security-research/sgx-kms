#pragma once

enum SGX_CRYPTO_API {
    CRYPTO_EXIT = -1,
    CRYPTO_STUB_PROC_MSG1_GEN_MSG2,
    CRYPTO_STUB_PROC_MSG3_GEN_MSG4,
    CRYPTO_MAX
};

extern char *SGX_CRYPTO_API_STRS[CRYPTO_MAX + 1];

#define COMMAND_TO_STRING(command) (((command) < -1) || ((command) >= (CRYPTO_MAX))) ? "INVALID" : SGX_CRYPTO_API_STRS[(command) + 1]

size_t write_buffer(char *pbuf, size_t buf_len);
size_t read_buffer(char **ppbuf, size_t *pbuf_len);
size_t read_command(int *command);
size_t initialize_fifo(char *to_me, char *from_me);
void destroy_fifo(char *to_me, char *from_me);

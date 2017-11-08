#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../Include/client_io.h"

char *SGX_CRYPTO_API_STRS[CRYPTO_MAX + 1] = {
	"EXIT",
	"CRYPTO_STUB_PROC_MSG1_GEN_MSG2",
	"CRYPTO_STUB_PROC_MSG3_GEN_MSG4",
};


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "../Include/server_io.h"
char *SGX_CRYPTO_API_STRS[CRYPTO_MAX + 1] = {
	"EXIT",
	"SUPPORTS",
	"INITIALIZE",
	"ENCRYPT",
	"DECRYPT",
	"GEN_KEY",
	"INIT_RA",
	"PROC_MSG2_GEN_MSG3",
	"PROC_MSG4",
};


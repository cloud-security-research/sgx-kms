#include "stdio.h"
#include "util.h"

void print_hex(const char *var_name, const char *buf, int buf_len)
{
    if (!var_name || !buf) return;
        printf("{%s:", var_name);
        for (int x = 0; x < buf_len; x++) {
            if (x % 8 == 0) printf("\n");
            printf("0x%x", buf + x);
        }
}

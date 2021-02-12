#include <stdio.h>
#include <stdint.h>
#include "cipher.h"
#include "encrypt.h"
#include "common.h"
#include "log.h"

int main (int argc, char **argv)
{
    // Assume data to enc/dec comes from stdin and prints bin output to stdout
    // Key and IV as arg
    // -K key in hex
    // -iv iv in hex

    uint8_t K[16];
    uint8_t iv[AES_BLOCK_LEN_BYTES];

    uint8_t *blk_dest;
    argv++;
    argc--;
    while (argc)
    {
        if (argv[0][0] == '-')
        {
            blk_dest = NULL;
            if (argv[0][1] == 'K')
            {
                blk_dest = K;
            }
            else if (argv[0][1] == 'i' && argv[0][2] == 'v')
            {
                blk_dest = iv;
            }
            else
            {
                printf("unrecognized arg:%s\n", &argv[0][0]);
                return 1;
            }

            // Assuming all input is 16bytes in hex, not checking
            for (int c = 0; c < AES_BLOCK_LEN_BYTES; c++)
            {
                unsigned int byte;
                sscanf(&argv[1][c * 2], "%2X", &byte);

                blk_dest[c] = byte;
            }

            argv++;
            argc--;
        }

        argv++;
        argc--;
    }

    aes_params_t aes_params;
    aes_params.mode = AES_MODE_CBC;
    aes_params.key = K;
    aes_params.iv = iv;

    aes_encrypt_fd(&aes_params, 0, 1);

    return 0;
}


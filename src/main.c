#define _POSIX_C_SOURCE 200809L // for dprintf

#include <stdio.h>
#include <stdint.h>
#include <string.h>
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
    // -M cbc or ecb

    aes_params_t aes_params;
    memset (&aes_params, 0, sizeof(aes_params));
    uint8_t K[AES_MAX_KEY_LEN_BYTES];
    uint8_t iv[AES_BLOCK_LEN_BYTES];

    uint8_t *blk_dest;
    argv++;
    argc--;
    while (argc)
    {
        // Args with a param
        if (argv[0][0] == '-')
        {
            blk_dest = NULL;
            if (argv[0][1] == 'M')
            {
                if (strcmp("ecb", &argv[1][0]) == 0)
                {
                    aes_params.mode = AES_MODE_ECB;
                }
                else if (strcmp("cbc", &argv[1][0]) == 0)
                {
                    aes_params.mode = AES_MODE_CBC;
                }
            }
            else if (argv[0][1] == 'K')
            {
                blk_dest = K;
                aes_params.key = K;
            }
            else if (argv[0][1] == 'i' && argv[0][2] == 'v')
            {
                blk_dest = iv;
                aes_params.iv = iv;
            }
            else
            {
                dprintf(2, "unrecognized arg:%s\n", &argv[0][0]);
                return 1;
            }

            // Assuming all input is 16bytes in hex, not checking
            if (blk_dest)
            {
                for (int c = 0; c < AES_BLOCK_LEN_BYTES; c++)
                {
                    unsigned int byte;
                    sscanf(&argv[1][c * 2], "%2X", &byte);

                    blk_dest[c] = byte;
                }
            }

            argv++;
            argc--;
        }

        argv++;
        argc--;
    }

    if (aes_params.key == NULL || aes_params.mode == AES_MODE_UNKNOWN)
    {
        dprintf(2, "No mode provided\n");
        return 1;
    }

    if (aes_params.mode == AES_MODE_CBC && aes_params.iv == NULL)
    {
        dprintf(2, "Missing iv\n");
        return 1;
    }

    if (aes_params.mode == AES_MODE_ECB && aes_params.iv != NULL)
    {
        dprintf(2, "Warn:ECB needs no iv\n");
    }

    aes_encrypt_fd(&aes_params, 0, 1);

    return 0;
}


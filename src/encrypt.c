#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include "encrypt.h"
#include "cipher.h"
#include "common.h"


static int aes_encrypt_one_block(const aes_params_t *aes_params,
                                 const uint8_t *restrict blockin, uint8_t *restrict blockout);
static int aes_encrypt_init(const aes_params_t *aes_params);
static int aes_encrypt_close();

static uint8_t iv[AES_BLOCK_LEN_BYTES];
// static long itr;

static int aes_encrypt_init(const aes_params_t *aes_params)
{
    if (aes_init() != 0)
        return -1;

    // itr = 0;
    memcpy(iv, aes_params->iv, AES_BLOCK_LEN_BYTES);

    aes_expand_key(aes_params->key, 16);

    return 0;
}

static int aes_encrypt_close()
{
    return aes_free();
}

int aes_encrypt_arrays(const aes_params_t *aes_params, uint8_t *restrict in, int size_in, uint8_t *restrict out, int size_out)
{
    if (aes_encrypt_init(aes_params) != 0)
        return -1;

    if (((size_in % 16) != 0) || size_out < size_in || in == NULL || out == NULL)
    {
        return -1;
    }

    for (int i = 0; i < size_in / 16; ++i)
    {
        if (aes_encrypt_one_block(aes_params, &in[i * 16], &out[i * 16]) != 0)
        {
            return -1;
        }
    }

    if (aes_encrypt_close() != 0)
        return -1;

    return 0;

}

int aes_encrypt_fd(const aes_params_t *aes_params, int fd_in, int fd_out)
{
    uint8_t blockbufin[AES_BLOCK_LEN_BYTES];
    uint8_t blockbufout[AES_BLOCK_LEN_BYTES];

    if (aes_encrypt_init(aes_params) != 0)
        return -1;

    /*
        // first  iter : Front = iv                 Back =out
        // Secont iter : Front = out(use as iv)     Back =iv
        uint8_t *iv_back  = blockbufout;
        uint8_t *iv_front = iv;
        while (read(fd_in, blockbufin, AES_BLOCK_LEN_BYTES) == AES_BLOCK_LEN_BYTES)
        {
            uint8_t *tmp;

            ret = aes_encrypt(AES_MODE_CBC, blockbufin, iv_back, AES_BLOCK_LEN_BYTES, K, iv_front);
            if (ret != 0)
            {
                puts("Error");
                return ret;
            }

            write(fd_out, iv_back, AES_BLOCK_LEN_BYTES);

            // Buff swap
            tmp = iv_back;
            iv_back = iv_front;
            iv_front = tmp;
        }
    */

    while (read(fd_in, blockbufin, AES_BLOCK_LEN_BYTES) == AES_BLOCK_LEN_BYTES)
    {
        if (aes_encrypt_one_block(aes_params, blockbufin, blockbufout) != 0)
        {
            return -1;
        }

        write(fd_out, blockbufout, AES_BLOCK_LEN_BYTES);
    }

    if (aes_encrypt_close() != 0)
        return -1;

    return 0;
}

static int aes_encrypt_one_block(const aes_params_t *aes_params,
                                 const uint8_t *restrict blockin, uint8_t *restrict blockout)
{
    uint8_t xored_in[AES_BLOCK_LEN_BYTES];

    if (aes_params->mode == AES_MODE_CBC)
    {
        for (int i = 0; i < AES_BLOCK_LEN_BYTES; ++i)
        {
            xored_in[i] = iv[i] ^ blockin[i];
        }

        aes_cipher_block(xored_in, blockout);

        // Prepare iv for next round
        memcpy(iv, blockout, 16);
    }
    else
    {
        //Other modes
        return -1;
    }

    return 0;
}

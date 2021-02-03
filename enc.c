#include <stddef.h>


#include "enc.h"
#include "aes.h"

int aes_encrypt(aes_mode_t mode, const uint8_t *restrict in, uint8_t *restrict out, int size,
                const uint8_t * restrict key, const uint8_t *restrict iv)
{
    uint8_t xored_in[16];

    if (size % 16)
    {
        // Not block aligned
        return -1;
    }

    aes_init();

    if (mode == AES_MODE_CBC)
    {

        if (iv == NULL)
        {
            // CBC needs IV
            return -1;
        }

        for (int round = 0; round < size / 16; ++round)
        {
            //16 bytes ptr
            const uint8_t * prec;

            if (round == 0)
            {
                prec = iv;
            }
            else
            {
                prec = &out[(round - 1) * 16];
            }

            for (int i = 0; i < 16; ++i)
            {
                xored_in[i] = prec[i] ^ in[round * 16 + i];
            }

            aes_encrypt_block(key, xored_in, &out[round * 16]);
        }
    }
    else
    {
        //Other modes
        return -1;
    }

    aes_free();

    return 0;
}

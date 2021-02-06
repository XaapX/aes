#pragma once

#include <stdint.h>

typedef enum
{
    AES_MODE_ECB,
    AES_MODE_CBC
} aes_mode_t;

int aes_encrypt(aes_mode_t mode, const uint8_t *restrict in, uint8_t *restrict out, int size,
                const uint8_t * restrict key, const uint8_t *restrict iv);

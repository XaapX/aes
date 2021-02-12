#pragma once

#include <stdint.h>

typedef enum
{
    AES_MODE_ECB,
    AES_MODE_CBC
} aes_mode_t;

typedef struct
{
    aes_mode_t mode;
    const uint8_t * restrict key;
    const uint8_t *restrict iv;
} aes_params_t;

int aes_encrypt_arrays(const aes_params_t *aes_params, uint8_t *restrict in, int size_in, uint8_t *restrict out, int size_out);
int aes_encrypt_fd(const aes_params_t *aes_params, int fd_in, int fd_out);

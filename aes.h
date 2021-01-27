#pragma once

#include <stdint.h>

int aes_init(void);
int aes_free(void);

void aes_encrypt_block(const uint8_t * restrict K, const uint8_t * restrict input, uint8_t * restrict output);
void aes_decrypt_block(const uint8_t * restrict K, const uint8_t * restrict input, uint8_t * restrict output);

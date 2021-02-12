#pragma once

#include <stdint.h>

int aes_init(void);
int aes_free(void);

void aes_expand_key(const uint8_t * restrict K, int size);
void aes_cipher_block(const uint8_t * restrict input, uint8_t * restrict output);
void aes_decipher_block(const uint8_t * restrict input, uint8_t * restrict output);

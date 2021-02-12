#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "cipher.h"
#include "log.h"
#include "common.h"

static void AddRoundKey(uint8_t * restrict state, const uint8_t * restrict rk);
static void MixColumns(uint8_t *state);
static void RotWord(const uint8_t * restrict in, uint8_t * restrict out);
static void ShiftRows(uint8_t *state);
static void SubBytes(uint8_t *state);
static void SubWord(const uint8_t * in, uint8_t * out);

// convert state coordinates to linear array byte index
inline static int ST_IDX(int row, int col)
{
    return (col * 4 ) + row;
}

// Number of columns (32-bit words) comprising the State
static const int Nb = 4;

// Number of 32-bit words comprising the Cipher Key.
static const int Nk = 4;

// Number of rounds, which is a function of Nk and Nb
static const int Nr = 10;

// The round constant word array
// contains the values given by [xi-1,{00},{00},{00}], with
// x i-1 being powers of x (x is denoted as {02}) in the field GF(28), as discussed in Sec. 4.2 (note
// that i starts at 1, not 0).
static uint8_t rcon[11 * 4] = {0};

static const uint8_t sbox[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                               0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                               0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                               0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                               0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                               0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                               0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                               0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                               0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                               0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                               0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                               0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                               0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                               0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                               0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                               0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
                              };

// Transformation in the Cipher and Inverse Cipher in which a Round
// Key is added to the State using an XOR operation. The length of a
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes).
static void AddRoundKey(uint8_t * restrict state, const uint8_t * restrict rk)
{
    for (int i = 0; i < AES_BLOCK_LEN_BYTES; ++i)
    {
        state[i] ^= rk[i];
    }
}

static uint8_t xtime(uint8_t x)
{
    int mod = x & 0x80;
    x = x << 1;

    if (mod)
    {
        x ^= 0x1b;
    }

    return x;
}

static void MixColumns(uint8_t *state)
{
    uint8_t oldstate[AES_BLOCK_LEN_BYTES];
    memcpy(oldstate, state, AES_BLOCK_LEN_BYTES);
    memset(state, 0 , AES_BLOCK_LEN_BYTES);

    // Very naive approach... Can be optimized
    for (int col = 0; col < 4; col++)
    {
        for (int row = 0; row < 4; row++)
        {
            state[ST_IDX(row, col)] ^= xtime(oldstate[ST_IDX(row, col)]);
            state[ST_IDX(row, col)] ^= xtime(oldstate[ST_IDX((row + 1) % 4, col)]) ^ oldstate[ST_IDX((row + 1) % 4, col)];
            state[ST_IDX(row, col)] ^= oldstate[ST_IDX((row + 2) % 4, col)];
            state[ST_IDX(row, col)] ^= oldstate[ST_IDX((row + 3) % 4, col)];
        }
    }
}

// Function used in the Key Expansion routine that takes a four-byte
// word and performs a cyclic permutation.
static void RotWord(const uint8_t * restrict in, uint8_t * restrict out)
{
    out[0] = in[1];
    out[1] = in[2];
    out[2] = in[3];
    out[3] = in[0];
}

// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets.
static void ShiftRows(uint8_t *state)
{
    uint8_t oldstate[AES_BLOCK_LEN_BYTES];
    memcpy(oldstate, state, AES_BLOCK_LEN_BYTES);

    for (int row = 1; row < 4; ++row)
    {
        for (int col = 0; col < 4; ++col)
        {
            state[ST_IDX(row, col)] = oldstate[ST_IDX(row, (col + row) % 4)];
        }
    }
}

// Transformation in the Cipher that processes the State using a non­
// linear byte substitution table (S-box) that operates on each of the
// State bytes independently.
static void SubBytes(uint8_t *state)
{
    for (int i = 0; i < 4; ++i)
    {
        SubWord(state + i * 4, state + i * 4);
    }
}

// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to
// produce an output word.
static void SubWord(const uint8_t * in, uint8_t * out)
{
    for (int i = 0; i < 4; ++i)
    {
        int x = in[i] >> 4;
        int y = in[i] & 15;

        out[i] = sbox[16 * x + y];
    }
}

// Expand the key to a key schedule array
// key : the key to expand
// w : the output key schedule (should be of size [4 * Nb * (Nr +1)] )
// Nk : Key size in words
static void KeyExpansion(const uint8_t *key, uint8_t *w, int Nk)
{
    if (Nk != 4)
        return;

    // first line of w is the key
    memcpy(w, key, Nk * 4);

    for (int i = Nk; i < Nb * (Nr + 1); ++i)
    {
        uint8_t temp[4];

        memcpy(temp, &w[(i - 1) * 4], 4);

        if (i % Nk == 0)
        {
            uint8_t rot_temp[4];
            RotWord (temp, rot_temp);
            SubWord (rot_temp, temp);

            int rcon_idx = (i / Nk) * 4;
            temp[0] ^= rcon[rcon_idx];
            temp[1] ^= rcon[rcon_idx + 1];
            temp[2] ^= rcon[rcon_idx + 2];
            temp[3] ^= rcon[rcon_idx + 3];

        }
        else if (Nk > 6 && (i % Nk == 4))
        {
            uint8_t temp_cpy[4];
            memcpy(temp_cpy, temp, 4);

            SubWord(temp_cpy, temp);
        }

        for (int ki = 0; ki < 4; ++ki)
        {
            w[i * 4 + ki] = w[(i - Nk) * 4 + ki];
            w[i * 4 + ki] ^= temp[ki];
        }
    }
}

static void Cipher(const uint8_t* restrict in, uint8_t* restrict out, const uint8_t* restrict w)
{
    uint8_t state[AES_BLOCK_LEN_BYTES];
    int round = 0;

    memcpy(state, in, AES_BLOCK_LEN_BYTES);

    AddRoundKey(state, &w[round]);

    for (round = 1; round <= Nr; ++round)
    {

        SubBytes(state);
        ShiftRows(state);
        if (round < Nr)
        {
            MixColumns(state);
        }
        AddRoundKey(state, &w[round * 16]);
    }

    memcpy(out, state, 16);
}

int aes_init(void)
{
    //Compute rcon
    for (int i = 1; i < 11; ++i)
    {
        if (i < 9)
        {
            rcon[i * 4] = 1 << (i - 1);
        }
        else
        {
            rcon[i * 4] = 0x1b << (i - 9);
        }
        //All the rest is already initialized to 0...
    }

    return 0;
}

int aes_free(void)
{
    return 0;
}

// XXX Global shared state...
static uint8_t w[4 * 4 * 11];

void aes_expand_key(const uint8_t * restrict K, int size)
{
    if (size != 16)
        exit(1);

    // Expand the key K to a key schedule array w
    KeyExpansion(K, w, Nk);
}

void aes_cipher_block(const uint8_t * restrict input, uint8_t * restrict output)
{
    // Call cipher with generated key schedule
    Cipher(input, output, w);
}

void aes_decipher_block(const uint8_t * restrict input, uint8_t * restrict output)
{
    (void)input;
    (void)output;
}

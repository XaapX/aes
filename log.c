#include <stdint.h>
#include "log.h"
#include "common.h"

#if DEBUG_ENABLE==1
#include <stdarg.h>
#endif

void db_printf(const char *format, ...)
{
#if DEBUG_ENABLE==1
    va_list args;
    va_start(args, format);

    vprintf(format, args);

    va_end(args);
#else
    (void)format;
#endif
}

//Print a state or any 16-byte block in a 2D form
void debug_print_state(const uint8_t *state)
{
    db_printf("\n");
    for (int r = 0; r < 4; ++r)
    {
        for (int c = 0; c < 4; ++c)
        {
            db_printf("%02x", state[4 * c + r]);
        }
        db_printf("\n");
    }
    db_printf("\n");
}

//Print a block or any 16-byte array in 1D form, following memory order
void debug_print_block(const uint8_t *block)
{
#if DEBUG_ENABLE==1
    print_block(block, 0);
#endif
}

void debug_trace_cipher_states(int round, const char *label, const uint8_t *block)
{
    db_printf("round[%2d].%s=", round, label);
    debug_print_block(block);
}


void print_block(const uint8_t *block, int blockdisp)
{
    if (blockdisp)
    {
        // Block mode TODO
    }
    else
    {
        for (int i = 0; i < AES_BLOCK_LEN_BYTES; ++i)
        {
            printf("%02x", block[i]);
        }
        printf("\n");
    }
}

void print_blocks(const uint8_t *block, int blocks, int blockdisp)
{
    for (int i = 0; i < blocks; ++i)
    {
        print_block(&block[i * 16], blockdisp);
    }
}

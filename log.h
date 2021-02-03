#pragma once

#include <stdio.h>

void db_printf(const char *format, ...);
void debug_print_state(const uint8_t *state);
void debug_print_block(const uint8_t *block);
void debug_trace_cipher_states(int round, const char *label, const uint8_t *block);

void print_block(const uint8_t *block, int blockdisp);
void print_blocks(const uint8_t *block, int blocks, int blockdisp);

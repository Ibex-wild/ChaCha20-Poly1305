/*
 * Copyright 2026 Ibex-wild (https://github.com/Ibex-wild)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "chacha20.h"
#include <string.h>

static const uint8_t chacha20_sigma[16] = {
    0x65, 0x78, 0x70, 0x61,
    0x6e, 0x64, 0x20, 0x33,
    0x32, 0x2d, 0x62, 0x79, 
    0x74, 0x65, 0x20, 0x6b 
};

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32U - n));
}

static uint32_t load32_le(const uint8_t src[4]) {
    return  ((uint32_t)src[0])       |
            ((uint32_t)src[1] << 8)  |
            ((uint32_t)src[2] << 16) |
            ((uint32_t)src[3] << 24);
}

static void store32_le(uint8_t dest[4], uint32_t v) {
    dest[0] = (uint8_t)(v);
    dest[1] = (uint8_t)(v >> 8);
    dest[2] = (uint8_t)(v >> 16);
    dest[3] = (uint8_t)(v >> 24);
}

static void quarter_round(uint32_t s[16],
                          unsigned a, unsigned b,
                          unsigned c, unsigned d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16U);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12U);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d],  8U);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b],  7U);
}

static void double_round(uint32_t s[16]) {
    quarter_round(s, 0, 4,  8, 12);
    quarter_round(s, 1, 5,  9, 13);
    quarter_round(s, 2, 6, 10, 14);
    quarter_round(s, 3, 7, 11, 15);
    quarter_round(s, 0, 5, 10, 15);
    quarter_round(s, 1, 6, 11, 12);
    quarter_round(s, 2, 7,  8, 13);
    quarter_round(s, 3, 4,  9, 14);
}

static void initial_state(uint32_t state[16],
                          const uint8_t key[CHACHA20_KEY_SIZE],
                          uint32_t counter,
                          const uint8_t nonce[CHACHA20_NONCE_SIZE]) {
    unsigned i;
    for (i = 0; i < 4U; i++) {
        state[i] = load32_le(&chacha20_sigma[i * 4U]);
    }
    for (i = 0; i < 8U; i++) {
        state[4U + i] = load32_le(&key[i * 4U]);
    }
    state[12] = counter;
    state[13] = load32_le(&nonce[0]);
    state[14] = load32_le(&nonce[4]);
    state[15] = load32_le(&nonce[8]);
}

static void compute_block(const uint32_t initial[16], uint8_t out[64]) {
    uint32_t working[16];
    unsigned r, i;

    memcpy(working, initial, sizeof(working));

    for (r = 0; r < (CHACHA20_ROUNDS / 2U); r++) {
        double_round(working);
    }
    for (i = 0; i < 16U; i++) {
        working[i] += initial[i];
    }
    for (i = 0; i < 16U; i++) {
        store32_le(&out[i * 4U], working[i]);
    }
    memset(working, 0, sizeof(working));
}

chacha20_error_t chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE],
                                uint32_t counter,
                                const uint8_t nonce[CHACHA20_NONCE_SIZE],
                                uint8_t out[CHACHA20_BLOCK_SIZE]) {
    uint32_t st[16];

    if (key == NULL || nonce == NULL || out == NULL) {
        return CHACHA20_ERR_NULL_PTR;
    }

    initial_state(st, key, counter, nonce);
    compute_block(st, out);
    memset(st, 0, sizeof(st));

    return CHACHA20_OK;
}

static void generate_keystream(chacha20_ctx *ctx) {
    compute_block(ctx->state, ctx->keystream);
    ctx->state[12] += 1U;
    ctx->keystream_pos = 0U;
}

chacha20_error_t chacha20_init(chacha20_ctx *ctx,
                               const uint8_t key[CHACHA20_KEY_SIZE],
                               uint32_t counter,
                               const uint8_t nonce[CHACHA20_NONCE_SIZE]) {
    if (ctx == NULL || key == NULL || nonce == NULL) {
        return CHACHA20_ERR_NULL_PTR;
    }

    initial_state(ctx->state, key, counter, nonce);
    memset(ctx->keystream, 0, sizeof(ctx->keystream));
    ctx->keystream_pos = CHACHA20_BLOCK_SIZE; 

    return CHACHA20_OK;
}

chacha20_error_t chacha20_xor(chacha20_ctx *ctx,
                              const uint8_t *input,
                              uint8_t *output,
                              size_t len) {
    size_t i;
    if (ctx == NULL) {
        return CHACHA20_ERR_NULL_PTR;
    }
    if (len > 0U && (input == NULL || output == NULL)) {
        return CHACHA20_ERR_NULL_PTR;
    }
    for (i = 0; i < len; i++) {
        if (ctx->keystream_pos >= CHACHA20_BLOCK_SIZE) {
            generate_keystream(ctx);
        }
        output[i] = input[i] ^ ctx->keystream[ctx->keystream_pos++];
    }
    return CHACHA20_OK;
}

const char *chacha20_strerror(chacha20_error_t err) {
    switch (err) {
        case CHACHA20_OK:                     return "success";
        case CHACHA20_ERR_NULL_PTR:           return "null pointer argument";
        case CHACHA20_ERR_INVALID_KEY_SIZE:   return "invalid key size";
        case CHACHA20_ERR_INVALID_NONCE_SIZE: return "invalid nonce size";
        default:                              return "unknown error";
    }
}

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
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_KEY_SIZE     32U
#define CHACHA20_NONCE_SIZE   12U
#define CHACHA20_BLOCK_SIZE   64U
#define CHACHA20_STATE_WORDS  16U
#define CHACHA20_ROUNDS       20U

typedef enum {
    CHACHA20_OK                      = 0,
    CHACHA20_ERR_NULL_PTR            = -1,
    CHACHA20_ERR_INVALID_KEY_SIZE    = -2,
    CHACHA20_ERR_INVALID_NONCE_SIZE  = -3
} chacha20_error_t;

typedef struct {
    uint32_t state[CHACHA20_STATE_WORDS];
    uint8_t  keystream[CHACHA20_BLOCK_SIZE];
    size_t   keystream_pos; 
} chacha20_ctx;

chacha20_error_t chacha20_block(const uint8_t key[CHACHA20_KEY_SIZE],
                                uint32_t counter,
                                const uint8_t nonce[CHACHA20_NONCE_SIZE],
                                uint8_t out[CHACHA20_BLOCK_SIZE]);

chacha20_error_t chacha20_init(chacha20_ctx *ctx,
                               const uint8_t key[CHACHA20_KEY_SIZE],
                               uint32_t counter,
                               const uint8_t nonce[CHACHA20_NONCE_SIZE]);

chacha20_error_t chacha20_xor(chacha20_ctx *ctx,
                              const uint8_t *input,
                              uint8_t *output,
                              size_t len);

const char *chacha20_strerror(chacha20_error_t err);

#ifdef __cplusplus
}
#endif

#endif

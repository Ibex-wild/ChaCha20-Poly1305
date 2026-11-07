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
#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20POLY1305_KEY_SIZE   32U
#define CHACHA20POLY1305_NONCE_SIZE 12U
#define CHACHA20POLY1305_TAG_SIZE   16U

typedef enum {
    CHACHA20POLY1305_OK        =  0,
    CHACHA20POLY1305_ERR_NULL  = -1,
    CHACHA20POLY1305_ERR_AUTH  = -2
} chacha20poly1305_error_t;

int chacha20poly1305_encrypt(
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE],
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *ciphertext,
    uint8_t tag[CHACHA20POLY1305_TAG_SIZE]);

int chacha20poly1305_decrypt(
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE],
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    uint8_t *plaintext);

#endif

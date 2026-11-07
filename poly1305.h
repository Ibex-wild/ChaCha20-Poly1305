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
#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t r[5];
    uint32_t h[5]; 
    uint32_t pad[4];
    uint8_t  buffer[16]; 
    size_t   leftover;
} poly1305_ctx;

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);
void poly1305_update(poly1305_ctx *ctx, const uint8_t *msg, size_t len);
void poly1305_final(poly1305_ctx *ctx, uint8_t tag[16]);

int poly1305_verify(const uint8_t tag1[16], const uint8_t tag2[16]);

void poly1305(const uint8_t *msg, size_t len, const uint8_t key[32], uint8_t tag[16]);

#endif

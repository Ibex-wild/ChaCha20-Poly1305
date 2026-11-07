# chacha20-poly1305

A small, dependency-free C11 implementation of ChaCha20-Poly1305 AEAD
as defined in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).

Nothing exotic here: no assembly, no SIMD intrinsics, no build system.
Just portable C you can drop into a project and read in one sitting.

## Contents

| File | Purpose |
|---|---|
| `chacha20.h` / `chacha20.c` | ChaCha20 stream cipher (block function + streaming XOR) |
| `poly1305.h` / `poly1305.c` | Poly1305 one-time MAC (streaming) |
| `chacha20poly1305.h` / `chacha20poly1305.c` | AEAD wrapper combining the two |
| `test_vector.c` | Test program with RFC 8439 test vectors |

## What it is

- ChaCha20 with 256-bit key, 96-bit nonce, 32-bit block counter (RFC variant).
- Poly1305 MAC with 256-bit one-time key.
- AEAD construction per RFC 8439 section 2.8: AAD, ciphertext, and length fields.
- Constant-time tag comparison.
- Decryption authenticates before it decrypts.

## What it is not

- Not constant-time with respect to secret key material in every code path.
  If you need hardened crypto against local attackers, use libsodium.
- No key derivation, no nonce management, no protocol.
- Not designed to resist power analysis, cache attacks, or fault injection.

For serious production use, prefer a vetted library. This exists for
learning, embedding in small projects, or as a reference.

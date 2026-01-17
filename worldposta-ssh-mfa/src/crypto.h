/*
 * WorldPosta SSH MFA - Cryptographic Utilities
 * Copyright (c) 2024 WorldPosta
 */

#ifndef WORLDPOSTA_CRYPTO_H
#define WORLDPOSTA_CRYPTO_H

#include <stddef.h>

#define NONCE_LENGTH 32
#define SIGNATURE_LENGTH 64

/*
 * Generate a random nonce (hex string)
 * Returns 0 on success, -1 on error
 */
int crypto_generate_nonce(char *nonce, size_t len);

/*
 * Compute HMAC-SHA256 signature
 * Returns 0 on success, -1 on error
 * Output is hex-encoded string
 */
int crypto_hmac_sha256(const char *key, const char *data, char *output, size_t output_len);

/*
 * Sign an API request
 * Creates signature from: timestamp + nonce + body
 * Returns 0 on success, -1 on error
 */
int crypto_sign_request(const char *secret_key, long timestamp, const char *nonce,
                        const char *body, char *signature, size_t sig_len);

#endif /* WORLDPOSTA_CRYPTO_H */

/*
 * WorldPosta SSH MFA - Cryptographic Utilities
 * Copyright (c) 2024 WorldPosta
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "crypto.h"

int crypto_generate_nonce(char *nonce, size_t len) {
    unsigned char random_bytes[16];

    if (len < NONCE_LENGTH + 1) {
        return -1;
    }

    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return -1;
    }

    /* Convert to hex string */
    for (int i = 0; i < 16; i++) {
        sprintf(nonce + (i * 2), "%02x", random_bytes[i]);
    }
    nonce[32] = '\0';

    return 0;
}

int crypto_hmac_sha256(const char *key, const char *data, char *output, size_t output_len) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (output_len < SIGNATURE_LENGTH + 1) {
        return -1;
    }

    unsigned char *result = HMAC(EVP_sha256(),
                                  key, strlen(key),
                                  (unsigned char *)data, strlen(data),
                                  digest, &digest_len);

    if (result == NULL) {
        return -1;
    }

    /* Convert to hex string */
    for (unsigned int i = 0; i < digest_len; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[digest_len * 2] = '\0';

    return 0;
}

int crypto_sign_request(const char *secret_key, long timestamp, const char *nonce,
                        const char *body, char *signature, size_t sig_len) {
    char *data;
    size_t data_len;
    int result;

    /* Build signing string: timestamp + nonce + body */
    data_len = 32 + strlen(nonce) + strlen(body) + 1;
    data = malloc(data_len);
    if (!data) {
        return -1;
    }

    snprintf(data, data_len, "%ld%s%s", timestamp, nonce, body);

    result = crypto_hmac_sha256(secret_key, data, signature, sig_len);

    free(data);
    return result;
}

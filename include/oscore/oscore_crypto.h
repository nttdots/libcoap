/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * @file oscore_crypto.h
 * @brief An implementation of the Hash Based Key Derivation Function (RFC) and wrappers for AES-CCM*.
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 *
 * adapted to libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#ifndef _OSCORE_CRYPTO_H
#define _OSCORE_CRYPTO_H

#include <coap3/coap_internal.h>

/**
 * @ingroup internal_api
 * @addtogroup oscore_internal
 * @{
 */

#define HKDF_INFO_MAXLEN 25
#define HKDF_OUTPUT_MAXLEN 25
#define AES_CCM_TAG 8

/* Plaintext Maxlen and Tag Maxlen is quite generous. */
#define AEAD_PLAINTEXT_MAXLEN COAP_MAX_CHUNK_SIZE
#define AEAD_TAG_MAXLEN COAP_MAX_CHUNK_SIZE


#if 0
#include <mbedtls/pk.h>

/* Returns =< 0 if failure to encrypt. Ciphertext length + tag length, otherwise.
   Tag length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length. */
int
oscore_mbedtls_encrypt_aes_ccm(int8_t alg, uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len,
        uint8_t *aad, size_t aad_len, uint8_t *plaintext_buffer, size_t plaintext_len, uint8_t *ciphertext_buffer);

 /* Return <= 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer or plaintext_buffer is of the correct length. */
int
oscore_mbedtls_decrypt_aes_ccm(uint8_t alg, uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len,
        uint8_t *aad, size_t aad_len, uint8_t *ciphertext_buffer, size_t ciphertext_len, uint8_t *plaintext_buffer);

/* ECP support for secp256r1 */
/* oscore_mbedtls_ecp_sign
 * signs the 256 bith has over the payload
 * algorithm is COSE_Algorithm_ES256 and params is COSE_curve_P_256
 * returns 0 when OK,
 * returns != 0 when error occurred
 */

int
oscore_mbedtls_ecp_verify(int8_t cose_alg, int8_t alg_param, uint8_t *signature,
size_t signature_len, uint8_t *payload, size_t payload_len, mbedtls_pk_context *mbed_ctx);

   /* oscore_mbedtls_ecp_verify
 * verifies the 256 bit hash over the payload
 * algorithm is COSE_Algorithm_ES256 and params is COSE_curve_P_256
 * returns 0 when OK,
 * returns != 0 when error occurred
 */

int
oscore_mbedtls_ecp_sign(int8_t cose_alg, int8_t alg_param, uint8_t *signature,
size_t *signature_len, uint8_t *payload, size_t payload_len, mbedtls_pk_context *mbed_ctx);
#endif

int
oscore_hmac_shaX(cose_alg_t alg, coap_bin_const_t *key,
                 coap_bin_const_t *data, coap_bin_const_t **hmac);

int
oscore_hkdf_extract(cose_alg_t alg, coap_bin_const_t *salt,
                    coap_bin_const_t *ikm, coap_bin_const_t **hkdf_extract);

int
oscore_hkdf_expand(cose_alg_t alg, coap_bin_const_t *prk, uint8_t *info,
                   size_t info_len, uint8_t *okm, size_t okm_len);

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_sign(cose_alg_t alg, cose_curve_t alg_param,
                  coap_binary_t *signature, coap_bin_const_t *ciphertext,
                  coap_bin_const_t *seed, coap_bin_const_t *public_key);

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_verify(cose_alg_t alg, cose_curve_t alg_param,
                    coap_binary_t *signature, coap_bin_const_t *plaintext,
                    coap_bin_const_t *public_key);

int oscore_hkdf(cose_alg_t alg, coap_bin_const_t *salt, coap_bin_const_t *ikm,
               uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/** @} */

#endif /* _OSCORE_CRYPTO_H */

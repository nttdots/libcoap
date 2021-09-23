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
 * @file oscore_crypto.c
 * @brief An implementation of the Hash Based Key Derivation Function (RFC) and wrappers for AES-CCM*.
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * extended for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#include "coap3/coap_internal.h"
#include "oscore/oscore_crypto.h"
#include <string.h>
#include "oscore/oscore.h"
#include "oscore/oscore_cose.h"

#include <stdio.h>
#ifdef HAVE_OSCORE_GROUP
#include "oscore_group_crypto/ed25519.h"
#endif /* HAVE_OSCORE_GROUP */
#include "oscore/oscore_context.h"

/*
 * return 1 fail
 *        0 OK
 */
int
oscore_hmac_shaX(cose_alg_t hkdf_alg, coap_bin_const_t *key,
                 coap_bin_const_t *data, coap_bin_const_t **hmac)
{
  if (!coap_crypto_hmac(hkdf_alg, key, data, hmac)) {
    coap_log(LOG_WARNING, "hmac_shaX: Failed hmac\n");
    return 1;
  }
  return 0;
}

/*
 * return 1 fail
 *        0 OK
 */
int
oscore_hkdf_extract(cose_alg_t hkdf_alg, coap_bin_const_t *salt,
                    coap_bin_const_t *ikm, coap_bin_const_t **hkdf_extract)
{
  assert(ikm);
  if (salt == NULL || salt->s == NULL) {
    uint8_t zeroes_data[32];
    coap_bin_const_t zeroes;

    memset(zeroes_data, 0, 32);
    zeroes.s = zeroes_data;
    zeroes.length = 32;

    return oscore_hmac_shaX(hkdf_alg, &zeroes, ikm, hkdf_extract);
  } else {
    return oscore_hmac_shaX(hkdf_alg, salt, ikm, hkdf_extract);
  }
}

/*
 * return 1 fail
 *        0 OK
 */
int
oscore_hkdf_expand(cose_alg_t hkdf_alg, coap_bin_const_t *prk, uint8_t *info,
                   size_t info_len, uint8_t *okm, size_t okm_len)
{
  size_t N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
  uint8_t *aggregate_buffer = coap_malloc(32 + info_len +1);
  uint8_t *out_buffer = coap_malloc((N+1)*32); /* 32 extra bytes to fit the last block */
  size_t i;
  coap_bin_const_t data;
  coap_bin_const_t *hkdf = NULL;

  /* Compose T(1) */
  memcpy(aggregate_buffer, info, info_len);
  aggregate_buffer[info_len] = 0x01;

  data.s = aggregate_buffer;
  data.length = info_len + 1;
  if (oscore_hmac_shaX(hkdf_alg, prk, &data, &hkdf) == 1)
    return 1;
  memcpy(&out_buffer[0], hkdf->s, hkdf->length);
  coap_delete_bin_const(hkdf);

  /* Compose T(2) -> T(N) */
  memcpy(aggregate_buffer, &(out_buffer[0]), 32);
  for(i = 1; i < N; i++) {
    memcpy(&(aggregate_buffer[32]), info, info_len);
    aggregate_buffer[32 + info_len] = (uint8_t)(i + 1);
    data.s = aggregate_buffer;
    data.length = 32 + info_len + 1;
    if (oscore_hmac_shaX(hkdf_alg, prk, &data, &hkdf)  == 1)
      return 1;
    memcpy(&out_buffer[i * 32], hkdf->s, hkdf->length);
    coap_delete_bin_const(hkdf);
    memcpy(aggregate_buffer, &(out_buffer[i * 32]), 32);
  }
  memcpy(okm, out_buffer, okm_len);
  coap_free(out_buffer);
  coap_free(aggregate_buffer);
  return 0;
}

/*
 * return 1 fail
 *        0 OK
 */
int
oscore_hkdf(cose_alg_t hkdf_alg, coap_bin_const_t *salt,
            coap_bin_const_t *ikm, uint8_t *info, size_t info_len,
            uint8_t *okm, size_t okm_len)
{
  int ret;
  coap_bin_const_t *hkdf_extract = NULL;
  if (oscore_hkdf_extract(hkdf_alg, salt, ikm, &hkdf_extract) == 1)
    return 1;
  ret = oscore_hkdf_expand(hkdf_alg, hkdf_extract, info, info_len, okm,
                         okm_len);
  coap_delete_bin_const(hkdf_extract);
  return ret;
}

#ifdef HAVE_OSCORE_GROUP
/* Return 0 if key pair generation failure. Key lengths are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

#if 0
int
oscore_edDSA_keypair(cose_alg_t alg, cose_curve_t alg_param,
                     uint8_t *private_key,
                     uint8_t *public_key, uint8_t *ed25519_seed)
{
  if (alg != COSE_Algorithm_EdDSA || alg_param != COSE_Elliptic_Curve_Ed25519) {
    return 0;
  }
  ed25519_create_keypair(public_key, private_key, ed25519_seed);

  if (coap_get_log_level() >= COAP_LOG_CIPHERS){
    coap_log(COAP_LOG_CIPHERS, "Key Pair\n");
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Public Key", public_key);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Private Key", private_key);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Seed", ed25519_seed);
  }

  return 1;
}
#endif

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_sign(cose_alg_t alg, cose_curve_t alg_param,
                  coap_binary_t *signature, coap_bin_const_t *ciphertext,
                  coap_bin_const_t *private_key, coap_bin_const_t *public_key)
{
  if (alg != COSE_Algorithm_EdDSA || alg_param != COSE_curve_Ed25519) {
    return 0;
  }

#ifdef HAVE_OPENSSL
  coap_crypto_sign(alg_param,signature, ciphertext, private_key, public_key);
#else /* ! HAVE_OPENSSL */
  ed25519_sign(signature->s, ciphertext->s, ciphertext->length, public_key->s,
               private_key->s);
#endif /* ! HAVE_OPENSSL */

  if (coap_get_log_level() >= COAP_LOG_CIPHERS){
    coap_log(COAP_LOG_CIPHERS, "Sign\n");
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Signature",
                         (coap_bin_const_t*)signature);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Ciphertext", ciphertext);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Private Key", private_key);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Public Key", public_key);
  }

  return 1;
}

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_verify(cose_alg_t alg, cose_curve_t alg_param,
                    coap_binary_t *signature, coap_bin_const_t *plaintext,
                    coap_bin_const_t *public_key)
{
  int res;

  if(alg != COSE_Algorithm_EdDSA || alg_param != COSE_curve_Ed25519) {
    return 0;
  }

  if (coap_get_log_level() >= COAP_LOG_CIPHERS){
    coap_log(COAP_LOG_CIPHERS, "Verify\n");
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Signature", (coap_bin_const_t*)signature);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Plaintext", plaintext);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "Public Key", public_key);
  }

#ifdef HAVE_OPENSSL
  res = coap_crypto_verify(alg_param, signature, plaintext, public_key);
#else /* ! HAVE_OPENSSL */
  res = ed25519_verify(signature->s, plaintext->s, plaintext->length,
                       public_key->s);
#endif /* ! HAVE_OPENSSL */
  return res;
}

#endif /* HAVE_OSCORE_GROUP */





/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

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
 * @brief An implementation of the Hash Based Key Derivation Function (RFC) and
 * wrappers for AES-CCM*.
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

#define HKDF_INFO_MAXLEN   25
#define HKDF_OUTPUT_MAXLEN 25
#define AES_CCM_TAG        8

/* Plaintext Maxlen and Tag Maxlen is quite generous. */
#define AEAD_PLAINTEXT_MAXLEN COAP_MAX_CHUNK_SIZE
#define AEAD_TAG_MAXLEN       COAP_MAX_CHUNK_SIZE

int oscore_hmac_shaX(cose_alg_t alg,
                     coap_bin_const_t *key,
                     coap_bin_const_t *data,
                     coap_bin_const_t **hmac);

int oscore_hkdf_extract(cose_alg_t alg,
                        coap_bin_const_t *salt,
                        coap_bin_const_t *ikm,
                        coap_bin_const_t **hkdf_extract);

int oscore_hkdf_expand(cose_alg_t alg,
                       coap_bin_const_t *prk,
                       uint8_t *info,
                       size_t info_len,
                       uint8_t *okm,
                       size_t okm_len);

/* Return 0 if signing failure. Signatue length otherwise, signature length and
 * key length are derived fron ed25519 values. No check is done to ensure that
 * buffers are of the correct length. */

int oscore_hkdf(cose_alg_t alg,
                coap_bin_const_t *salt,
                coap_bin_const_t *ikm,
                uint8_t *info,
                size_t info_len,
                uint8_t *okm,
                size_t okm_len);

/** @} */

#endif /* _OSCORE_CRYPTO_H */

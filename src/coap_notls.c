/*
 * coap_notls.c -- Stub Datagram Transport Layer Support for libcoap
 *
 * Copyright (C) 2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_notls.c
 * @brief NoTLS specific interface functions
 */

#include "coap3/coap_internal.h"

#if !defined(HAVE_LIBTINYDTLS) && !defined(HAVE_OPENSSL) && !defined(HAVE_LIBGNUTLS) && !defined(HAVE_MBEDTLS)

int
coap_dtls_is_supported(void) {
  return 0;
}

int
coap_tls_is_supported(void) {
  return 0;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = 0;
  version.type = COAP_TLS_LIBRARY_NOTLS;
  return &version;
}

int
coap_dtls_context_set_pki(coap_context_t *ctx COAP_UNUSED,
                          const coap_dtls_pki_t* setup_data COAP_UNUSED,
                          const coap_dtls_role_t role COAP_UNUSED
) {
  return 0;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *ctx COAP_UNUSED,
                                   const char *ca_file COAP_UNUSED,
                                   const char *ca_path COAP_UNUSED
) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
int
coap_dtls_context_set_cpsk(coap_context_t *ctx COAP_UNUSED,
                          coap_dtls_cpsk_t* setup_data COAP_UNUSED
) {
  return 0;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
int
coap_dtls_context_set_spsk(coap_context_t *ctx COAP_UNUSED,
                          coap_dtls_spsk_t* setup_data COAP_UNUSED
) {
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx COAP_UNUSED)
{
  return 0;
}

static int dtls_log_level = 0;

void coap_dtls_startup(void) {
}

void *
coap_dtls_get_tls(const coap_session_t *c_session COAP_UNUSED,
                  coap_tls_library_t *tls_lib) {
  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_NOTLS;
  return NULL;
}

void coap_dtls_shutdown(void) {
}

void
coap_dtls_set_log_level(int level) {
  dtls_log_level = level;
}

int
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

void *
coap_dtls_new_context(coap_context_t *coap_context COAP_UNUSED) {
  return NULL;
}

void
coap_dtls_free_context(void *handle COAP_UNUSED) {
}

#if COAP_SERVER_SUPPORT
void *coap_dtls_new_server_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
void *coap_dtls_new_client_session(coap_session_t *session COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

void coap_dtls_free_session(coap_session_t *coap_session COAP_UNUSED) {
}

void coap_dtls_session_update_mtu(coap_session_t *session COAP_UNUSED) {
}

int
coap_dtls_send(coap_session_t *session COAP_UNUSED,
  const uint8_t *data COAP_UNUSED,
  size_t data_len COAP_UNUSED
) {
  return -1;
}

int coap_dtls_is_context_timeout(void) {
  return 1;
}

coap_tick_t coap_dtls_get_context_timeout(void *dtls_context COAP_UNUSED) {
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *session COAP_UNUSED, coap_tick_t now COAP_UNUSED) {
  return 0;
}

void coap_dtls_handle_timeout(coap_session_t *session COAP_UNUSED) {
}

int
coap_dtls_receive(coap_session_t *session COAP_UNUSED,
  const uint8_t *data COAP_UNUSED,
  size_t data_len COAP_UNUSED
) {
  return -1;
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_hello(coap_session_t *session COAP_UNUSED,
  const uint8_t *data COAP_UNUSED,
  size_t data_len COAP_UNUSED
) {
  return 0;
}
#endif /* COAP_SERVER_SUPPORT */

unsigned int coap_dtls_get_overhead(coap_session_t *session COAP_UNUSED) {
  return 0;
}

#if COAP_CLIENT_SUPPORT
void *coap_tls_new_client_session(coap_session_t *session COAP_UNUSED, int *connected COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *coap_tls_new_server_session(coap_session_t *session COAP_UNUSED, int *connected COAP_UNUSED) {
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

void coap_tls_free_session(coap_session_t *coap_session COAP_UNUSED) {
}

ssize_t coap_tls_write(coap_session_t *session COAP_UNUSED,
                       const uint8_t *data COAP_UNUSED,
                       size_t data_len COAP_UNUSED
) {
  return -1;
}

ssize_t coap_tls_read(coap_session_t *session COAP_UNUSED,
                      uint8_t *data COAP_UNUSED,
                      size_t data_len COAP_UNUSED
) {
  return -1;
}

#if COAP_SERVER_SUPPORT
typedef struct coap_local_hash_t {
  size_t ofs;
  coap_key_t key[8];   /* 32 bytes in total */
} coap_local_hash_t;

coap_digest_ctx_t *
coap_digest_setup(void) {
  coap_key_t *digest_ctx = coap_malloc(sizeof(coap_local_hash_t));

  if (digest_ctx) {
    memset(digest_ctx, 0, sizeof(coap_local_hash_t));
  }

  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  coap_free(digest_ctx);
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
  coap_local_hash_t *local = (coap_local_hash_t*)digest_ctx;

  coap_hash(data, data_len, local->key[local->ofs]);

  local->ofs = (local->ofs + 1) % 7;
  return 1;
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
  coap_local_hash_t *local = (coap_local_hash_t*)digest_ctx;

  memcpy(digest_buffer, local->key, sizeof(coap_digest_t));

  coap_digest_free(digest_ctx);
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if defined(HAVE_OSCORE)

int
coap_oscore_is_supported(void) {
  return 0;
}

int
coap_oscore_group_is_supported(void) {
  return 0;
}

int
coap_oscore_edhoc_is_supported(void) {
  return 0;
}

/*
 * These are currently just stub functions as no crypto support is
 * provided.
 * TODO Add in RIOT OS support etc.
 */

/*
 * The struct cipher_algs and the function get_cipher_alg() are used to
 * determine which cipher type to use for creating the required cipher
 * suite object.
 */
static struct cipher_algs {
  cose_alg_t alg;
  u_int cipher_type;
} ciphers[] = {
    {COSE_Algorithm_AES_CCM_16_64_128, 1},
};

static u_int
get_cipher_alg(cose_alg_t alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(ciphers) / sizeof(struct cipher_algs); idx++) {
    if (ciphers[idx].alg == alg)
      return ciphers[idx].cipher_type;
  }
  coap_log(LOG_DEBUG, "get_cipher_alg: COSE cipher %d not supported\n", alg);
  return 0;
}

/*
 * The struct hmac_algs and the function get_hmac_alg() are used to
 * determine which hmac type to use for creating the required hmac
 * suite object.
 */
static struct hmac_algs {
  cose_alg_t alg;
  u_int hmac_type;
} hmacs[] = {
    {COSE_Algorithm_HMAC256_256, 1},
};

static u_int
get_hmac_alg(cose_alg_t alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(hmacs) / sizeof(struct hmac_algs); idx++) {
    if (hmacs[idx].alg == alg)
      return hmacs[idx].hmac_type;
  }
  coap_log(LOG_DEBUG, "get_hmac_alg: COSE hkdf %d not supported\n", alg);
  return 0;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  return 0;
  return get_cipher_alg(alg);
}

int
coap_crypto_check_hkdf_alg(cose_alg_t alg) {
  return 0;
  return get_hmac_alg(alg);
}

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)aad;
  (void)result;
  *max_result_len = 0;
  return 0;
}

int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {
  (void)params;
  (void)data;
  (void)aad;
  (void)result;
  *max_result_len = 0;
  return 0;
}

int
coap_crypto_hmac(cose_alg_t alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  (void)alg;
  (void)key;
  (void)data;
  (void)hmac;
  return 0;
}

#if HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC
int
coap_crypto_check_curve_alg(cose_curve_t alg) {
  (void)alg;
  return 0;
}

int
coap_crypto_read_pem_private_key(const char *filename,
                                 coap_crypto_pri_key_t **private) {
  (void)filename;
  (void)private;
  return 0;
}

int
coap_crypto_read_asn1_private_key(coap_bin_const_t *binary,
                                  coap_crypto_pri_key_t **private) {
  (void)binary;
  (void)private;
  return 0;
}

int
coap_crypto_read_raw_private_key(cose_curve_t curve,
                                 coap_bin_const_t *binary,
                                 coap_crypto_pri_key_t **private) {
  (void)curve;
  (void)binary;
  (void)private;
  return 0;
}

coap_crypto_pri_key_t *
coap_crypto_duplicate_private_key(coap_crypto_pri_key_t *key) {
  (void)key;
  return NULL;
}

void
coap_crypto_delete_private_key(coap_crypto_pri_key_t *key) {
  (void)key;
}

int
coap_crypto_read_pem_public_key(const char *filename,
                                coap_crypto_pub_key_t **public) {
  (void)filename;
  (void)public;
  return 0;
}

int
coap_crypto_read_asn1_public_key(coap_bin_const_t *binary,
                                 coap_crypto_pub_key_t **public) {
  (void)binary;
  (void)public;
  return 0;
}

int
coap_crypto_read_raw_public_key(cose_curve_t curve,
                                coap_bin_const_t *binary,
                                coap_crypto_pub_key_t **public) {
  (void)curve;
  (void)binary;
  (void)public;
  return 0;
}

coap_crypto_pub_key_t *
coap_crypto_duplicate_public_key(coap_crypto_pub_key_t *key) {
  (void)key;
  return NULL;
}

void
coap_crypto_delete_public_key(coap_crypto_pub_key_t *key) {
  (void)key;
}

int
coap_crypto_sign(cose_curve_t curve,
                 coap_binary_t *signature,
                 coap_bin_const_t *ciphertext,
                 coap_crypto_pri_key_t *private_key,
                 coap_crypto_pub_key_t *public_key) {
  (void)curve;
  (void)signature;
  (void)ciphertext;
  (void)private_key;
  (void)public_key;
  return 0;
}

int
coap_crypto_verify(cose_curve_t curve,
                   coap_binary_t *signature,
                   coap_bin_const_t *plaintext,
                   coap_crypto_pub_key_t *public_key) {
  (void)curve;
  (void)signature;
  (void)plaintext;
  (void)public_key;
  return 0;
}

int
coap_crypto_gen_pkey(cose_curve_t curve,
                     coap_bin_const_t **private,
                     coap_bin_const_t **public) {
  (void)curve;
  (void)private;
  (void)public;
  return 0;
}

int
coap_crypto_derive_shared_secret(cose_curve_t curve,
                                 coap_bin_const_t *local_private,
                                 coap_bin_const_t *peer_public,
                                 coap_bin_const_t **shared_secret) {
  (void)curve;
  (void)local_private;
  (void)peer_public;
  (void)shared_secret;
  return 0;
}

int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  (void)alg;
  (void)data;
  (void)hash;
  return 0;
}

#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC */

#endif /* HAVE_OSCORE */

#else /* !HAVE_LIBTINYDTLS && !HAVE_OPENSSL && !HAVE_LIBGNUTLS */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void dummy(void) {
}

#endif /* !HAVE_LIBTINYDTLS && !HAVE_OPENSSL && !HAVE_LIBGNUTLS && !HAVE_MBEDTLS */

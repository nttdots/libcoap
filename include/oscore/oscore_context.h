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
 * @file oscore_context.h
 * @brief An implementation of the Object Security for Constrained RESTful Enviornments (RFC 8613).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted to libcoap; added group communication
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

#include "coap3/coap_internal.h"
#include "oscore/oscore_cose.h"
#include "oscore/oscore_edhoc.h"
#include <stdint.h>

/**
 * @ingroup internal_api
 * @addtogroup oscore_internal
 * @{
 */

#define CONTEXT_KEY_LEN 16
#define COAP_TOKEN_LEN 8   // added
#define TOKEN_SEQ_NUM  2     // to be set by application
#define EP_CTX_NUM  10       // to be set by application
#define CONTEXT_INIT_VECT_LEN 13
#define CONTEXT_SEQ_LEN sizeof(uint64_t)
#define Ed25519_PRIVATE_KEY_LEN 32
#define Ed25519_PUBLIC_KEY_LEN 32
#define Ed25519_SEED_LEN 32
#define Ed25519_SIGNATURE_LEN 64

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

typedef enum {
  OSCORE_MODE_SINGLE = 0, /**< Vanilla RFC8613 support */
  OSCORE_MODE_GROUP,      /**< TODO draft-ietf-core-oscore-groupcomm */
  OSCORE_MODE_PAIRWISE    /**< TODO draft-ietf-core-oscore-groupcomm */
} oscore_mode_t;

typedef struct oscore_sender_ctx_t oscore_sender_ctx_t;
typedef struct oscore_recipient_ctx_t oscore_recipient_ctx_t;
typedef struct oscore_association_t oscore_association_t;

struct oscore_ctx_t {
  struct oscore_ctx_t *next;
  coap_bin_const_t *master_secret;
  coap_bin_const_t *master_salt;
  coap_bin_const_t *common_iv; /**< Derived from Master Secret,
                                    Master Salt, and ID Context */
  coap_bin_const_t *id_context;  /* contains GID in case of group */
  oscore_sender_ctx_t *sender_context;
  oscore_recipient_ctx_t *recipient_chain;
  cose_alg_t aead_alg;
  cose_alg_t hkdf_alg;
  oscore_mode_t mode;
  uint32_t ssn_freq;              /**< Sender Seq Num update frequency */
  uint32_t replay_window_size;
  coap_oscore_save_seq_num_t save_seq_num_func; /**< Called every seq num
                                                     change */
  void *save_seq_num_func_param; /**< Passed to save_seq_num_func() */
#ifdef HAVE_OSCORE_GROUP
  coap_bin_const_t *gm_public_key;
  coap_bin_const_t *sign_params;      /* binary CBOR array */
  cose_alg_t sign_enc_alg;
  cose_alg_t sign_alg;
  coap_bin_const_t *group_enc_key;
  cose_alg_t pairwise_agree_alg;
#endif /* HAVE_OSCORE_GROUP */
#ifdef HAVE_OSCORE_EDHOC
  edhoc_method_t edhoc_method;    /**< EDHOC method */
  int *edhoc_suite;               /**< Set of valid EDHOC suites */
  uint32_t edhoc_suite_cnt;       /**< Number of EDHOC suite entries */
#endif /* HAVE_OSCORE_EDHOC */
};

struct oscore_sender_ctx_t {
  uint64_t seq;
  uint64_t next_seq;             /**< Used for ssn_freq updating */
  coap_bin_const_t *sender_key;
  coap_bin_const_t *sender_id;
#if HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC
  /* addition for group communication */
  coap_bin_const_t *public_key;
  coap_bin_const_t *private_key;
  /* addition for pairwise communication */
  coap_bin_const_t *pairwise_sender_key;
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC */
#if HAVE_OSCORE_EDHOC
  coap_bin_const_t *test_public_key;
  coap_bin_const_t *test_private_key;
  coap_bin_const_t *edhoc_dh_subject;
#endif /* HAVE_OSCORE_EDHOC */
};

struct oscore_recipient_ctx_t {
  oscore_recipient_ctx_t *next_recipient;
            /* This field allows recipient chaining */
  oscore_ctx_t *common_ctx;
  uint64_t last_seq;
//  uint64_t highest_seq;
  uint64_t sliding_window;
  uint64_t rollback_sliding_window;
  uint64_t rollback_last_seq;
  coap_bin_const_t *recipient_key;
  coap_bin_const_t *recipient_id;
  uint8_t echo_value[8];
  uint8_t initial_state;
#ifdef HAVE_OSCORE_GROUP
  /* addition for group communication */
  coap_bin_const_t *public_key;
  /* addition for pairwise communication */
  coap_bin_const_t *pairwise_recipient_key;
#endif /* HAVE_OSCORE_GROUP */
};

#define OSCORE_ASSOCIATIONS_ADD(r, obj) \
  HASH_ADD(hh, (r), token->s[0], (obj)->token->length, (obj))

#define OSCORE_ASSOCIATIONS_DELETE(r, obj) \
  HASH_DELETE(hh, (r), (obj))

#define OSCORE_ASSOCIATIONS_ITER(r,tmp)  \
  oscore_associations_t *tmp, *rtmp; \
  HASH_ITER(hh, (r), tmp, rtmp)

#define OSCORE_ASSOCIATIONS_ITER_SAFE(e, el, rtmp) \
for ((el) = (e); (el) && ((rtmp) = (el)->hh.next, 1); (el) = (rtmp))

#define OSCORE_ASSOCIATIONS_FIND(r, k, res) {                     \
    HASH_FIND(hh, (r), (k)->s, (k)->length, (res)); \
  }

struct oscore_association_t {
  UT_hash_handle hh;
  oscore_recipient_ctx_t *recipient_ctx;
  coap_bin_const_t *token;
  coap_bin_const_t *aad;
  coap_bin_const_t *nonce;
  coap_bin_const_t *partial_iv;
  coap_tick_t last_seen;
  uint8_t is_observe;
};

void
oscore_enter_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx);

oscore_ctx_t *
oscore_derive_ctx(coap_bin_const_t *master_secret,
                  coap_bin_const_t *master_salt,
                  cose_alg_t cipher_alg, cose_alg_t hamc_alg,
                  coap_bin_const_t *sid,
                  coap_bin_const_t *rid,
                  coap_bin_const_t *id_context,
                  int *suite,
                  size_t suite_cnt,
                  int method,
                  uint32_t replay_window, uint32_t ssn_freq,
                  coap_oscore_save_seq_num_t save_seq_num_func,
                  void *save_seq_num_func_param,
                  uint64_t start_seq_num);

void
oscore_free_context(oscore_ctx_t *osc_ctx);

void
oscore_free_contexts(coap_context_t *c_context);

int
oscore_remove_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx);

oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *ctx,
                     coap_bin_const_t *rid);

int
oscore_delete_recipient(oscore_ctx_t *osc_ctx,
                       coap_bin_const_t *rid);

void
oscore_add_pair_keys(oscore_ctx_t *ctx,
                     oscore_recipient_ctx_t *recipient_ctx,
                     uint8_t *pairwise_recipient_key,
                     uint8_t pairwise_recipient_key_len,
                     uint8_t *pairwise_sender_key,
                     uint8_t pairwise_sender_key_len);


void
oscore_add_group_keys(oscore_ctx_t *ctx,
                      oscore_recipient_ctx_t *recipient_ctx,
                      coap_bin_const_t *snd_public_key,
                      coap_bin_const_t *snd_private_key,
                      coap_bin_const_t *rcp_public_key);

void
oscore_add_group_algorithm(oscore_ctx_t *ctx,
                           cose_alg_t  counter_signature_enc_algorithm,
                           cose_alg_t  counter_signature_algorithm,
                           uint8_t *counter_signature_parameters,
                           uint8_t counter_signature_parameters_len);

int _strcmp(const char *a, const char *b);

uint8_t
oscore_bytes_equal(uint8_t *a_ptr, uint8_t a_len, uint8_t *b_ptr, uint8_t b_len);

void oscore_convert_to_hex(const uint8_t *src, size_t src_len,
                           char *dest, size_t dst_len);

void
oscore_log_hex_value(coap_log_t level, const char *name,
                     coap_bin_const_t *value);

void
oscore_log_int_value(coap_log_t level, const char *name, int value);

//
//  oscore_find_context
// finds context for received send_id, reciever_id, or context_id
// that is stored in cose->key_id
// used by client interface
oscore_ctx_t *
oscore_find_context(coap_context_t *c_context,
                    coap_bin_const_t sndkey_id,
                    coap_bin_const_t rcpkey_id,
                    coap_bin_const_t ctxkey_id,
                    oscore_recipient_ctx_t **recipient_ctx);

void oscore_free_association(oscore_association_t *association);

int oscore_new_association(coap_session_t *session,
                           coap_bin_const_t *token,
                           oscore_recipient_ctx_t *recipient_ctx,
                           coap_bin_const_t *aad, coap_bin_const_t *nonce,
                           coap_bin_const_t *partial_iv, int is_observe);

oscore_association_t * oscore_find_association(coap_session_t *session,
                                               coap_bin_const_t *token);

int oscore_delete_association(coap_session_t *session,
                               oscore_association_t *association);

void oscore_delete_server_associations(coap_session_t *session);

int oscore_derive_keystream(oscore_ctx_t *osc_ctx, cose_encrypt0_t *code,
                            uint8_t coap_request,
                            coap_bin_const_t *sender_key,
                            coap_bin_const_t *id_context, size_t cs_size,
                            uint8_t *keystream, size_t keystream_size);

/** @} */

#endif /* _OSCORE_CONTEXT_H */

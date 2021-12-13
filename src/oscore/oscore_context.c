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
 * @file oscore_context.c
 * @brief An implementation of the Object Security for Constrained RESTful
 * Enviornments (RFC 8613). \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 */

#include "coap3/coap_internal.h"
#include "oscore/oscore_context.h"
#include <stddef.h>
#include <stdlib.h>
#include "oscore/oscore_cbor.h"
#include <string.h>
#include "oscore/oscore_crypto.h"
#include "oscore/oscore.h"

#include <stdio.h>

static void oscore_enter_context(coap_context_t *c_context,
                                 oscore_ctx_t *osc_ctx);

static size_t
compose_info(uint8_t *buffer,
             size_t buf_size,
             uint8_t alg,
             coap_bin_const_t *id,
             coap_bin_const_t *id_context,
             coap_str_const_t *type,
             size_t out_len) {
  size_t ret = 0;
  size_t rem_size = buf_size;

  ret += oscore_cbor_put_array(&buffer, &rem_size, 5);
  ret += oscore_cbor_put_bytes(&buffer,
                               &rem_size,
                               id ? id->s : NULL,
                               id ? id->length : 0);
  if (id_context != NULL && id_context->length > 0) {
    ret += oscore_cbor_put_bytes(&buffer,
                                 &rem_size,
                                 id_context->s,
                                 id_context->length);
  } else {
    ret += oscore_cbor_put_nil(&buffer, &rem_size);
  }
  ret += oscore_cbor_put_unsigned(&buffer, &rem_size, alg);
  ret += oscore_cbor_put_text(&buffer,
                              &rem_size,
                              (const char *)type->s,
                              type->length);
  ret += oscore_cbor_put_unsigned(&buffer, &rem_size, out_len);
  return ret;
}

#ifdef HAVE_OSCORE_GROUP
int
oscore_derive_keystream(oscore_ctx_t *osc_ctx,
                        cose_encrypt0_t *cose,
                        uint8_t coap_request,
                        coap_bin_const_t *sender_id,
                        coap_bin_const_t *id_context,
                        size_t cs_size,
                        uint8_t *keystream,
                        size_t keystream_size) {
  uint8_t info_buffer[30];
  uint8_t *buffer = info_buffer;
  size_t info_len = 0;
  size_t rem_size = sizeof(info_buffer);
  ;

  info_len += oscore_cbor_put_array(&buffer, &rem_size, 4);
  /* 1. id */
  info_len += oscore_cbor_put_bytes(&buffer,
                                    &rem_size,
                                    sender_id->s,
                                    sender_id->length);
  /* 2. id_context */
  info_len += oscore_cbor_put_bytes(&buffer,
                                    &rem_size,
                                    id_context->s,
                                    id_context->length);
  /* 3. type */
  if (coap_request)
    info_len += oscore_cbor_put_true(&buffer, &rem_size);
  else
    info_len += oscore_cbor_put_false(&buffer, &rem_size);
  /* 4. L */
  info_len += oscore_cbor_put_unsigned(&buffer, &rem_size, cs_size);

  oscore_hkdf(osc_ctx->hkdf_alg,
              &cose->partial_iv,
              osc_ctx->group_enc_key,
              info_buffer,
              info_len,
              keystream,
              keystream_size);
  return 1;
}
#endif /* HAVE_OSCORE_GROUP */

uint8_t
oscore_bytes_equal(uint8_t *a_ptr,
                   uint8_t a_len,
                   uint8_t *b_ptr,
                   uint8_t b_len) {
  if (a_len != b_len) {
    return 0;
  }

  if (memcmp(a_ptr, b_ptr, a_len) == 0) {
    return 1;
  } else {
    return 0;
  }
}

static void
oscore_enter_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx) {
  if (c_context->p_osc_ctx) {
    oscore_ctx_t *prev = c_context->p_osc_ctx;
    oscore_ctx_t *next = c_context->p_osc_ctx->next;

    while (next) {
      prev = next;
      next = next->next;
    }
    prev->next = osc_ctx;
  } else
    c_context->p_osc_ctx = osc_ctx;
}

static void
oscore_free_recipient(oscore_recipient_ctx_t *recipient) {
  coap_delete_bin_const(recipient->recipient_id);
  coap_delete_bin_const(recipient->recipient_key);
#ifdef HAVE_OSCORE_GROUP
  coap_crypto_delete_public_key(recipient->public_key);
#endif /* HAVE_OSCORE_GROUP */
  coap_free_type(COAP_OSCORE_REC, recipient);
}

void
oscore_free_context(oscore_ctx_t *osc_ctx) {
  if (osc_ctx == NULL)
    return;
  if (osc_ctx->sender_context) {
    coap_delete_bin_const(osc_ctx->sender_context->sender_id);
    coap_delete_bin_const(osc_ctx->sender_context->sender_key);
#if HAVE_OSCORE_GROUP
    coap_crypto_delete_private_key(osc_ctx->sender_context->private_key);
    coap_crypto_delete_public_key(osc_ctx->sender_context->public_key);
#endif /* HAVE_OSCORE_GROUP */
#if HAVE_OSCORE_EDHOC
    coap_delete_bin_const(osc_ctx->sender_context->test_s_private_key);
    coap_delete_bin_const(osc_ctx->sender_context->test_s_public_key);
    coap_delete_bin_const(osc_ctx->sender_context->test_r_private_key);
    coap_delete_bin_const(osc_ctx->sender_context->test_r_public_key);
    coap_delete_bin_const(osc_ctx->sender_context->edhoc_dh_subject);
#endif /* HAVE_OSCORE_EDHOC */
    coap_free_type(COAP_OSCORE_SEN, osc_ctx->sender_context);
  }

  while (osc_ctx->recipient_chain) {
    oscore_recipient_ctx_t *next = osc_ctx->recipient_chain->next_recipient;

    oscore_free_recipient(osc_ctx->recipient_chain);
    osc_ctx->recipient_chain = next;
  }

  coap_delete_bin_const(osc_ctx->master_secret);
  coap_delete_bin_const(osc_ctx->master_salt);
  coap_delete_bin_const(osc_ctx->id_context);
  coap_delete_bin_const(osc_ctx->common_iv);
#ifdef HAVE_OSCORE_GROUP
  coap_delete_bin_const(osc_ctx->sign_params);
  coap_delete_bin_const(osc_ctx->group_enc_key);
#endif /* HAVE_OSCORE_GROUP */
#if HAVE_OSCORE_EDHOC
  coap_free(osc_ctx->edhoc_suite);
#endif /* HAVE_OSCORE_EDHOC */
  coap_free_type(COAP_OSCORE_COM, osc_ctx);
}

void
oscore_free_contexts(coap_context_t *c_context) {
  while (c_context->p_osc_ctx) {
    oscore_ctx_t *osc_ctx = c_context->p_osc_ctx;

    c_context->p_osc_ctx = osc_ctx->next;

    oscore_free_context(osc_ctx);
  }
}

int
oscore_remove_context(coap_context_t *c_context, oscore_ctx_t *osc_ctx) {
  oscore_ctx_t *prev = NULL;
  oscore_ctx_t *next = c_context->p_osc_ctx;
  while (next) {
    if (next == osc_ctx) {
      if (prev != NULL)
        prev->next = next->next;
      else
        c_context->p_osc_ctx = next->next;
      oscore_free_context(next);
      return 1;
    }
    next = next->next;
  }
  return 0;
}

/*
 *  oscore_find_context
 * Finds OSCORE context for rcpkey_id and optional ctxkey_id
 * rcpkey_id can be 0 length.
 * Updates recipient_ctx.
 */
oscore_ctx_t *
oscore_find_context(coap_context_t *c_context,
                    coap_bin_const_t rcpkey_id,
                    coap_bin_const_t *ctxkey_id,
                    uint8_t *oscore_r2,
                    oscore_recipient_ctx_t **recipient_ctx) {
  oscore_ctx_t *pt = c_context->p_osc_ctx;

  *recipient_ctx = NULL;
  assert(rcpkey_id.length == 0 || rcpkey_id.s != NULL);
  while (pt != NULL) {
    int ok = 0;
    oscore_recipient_ctx_t *rpt = pt->recipient_chain;

    while (rpt) {
      ok = 0;
      if (rcpkey_id.length == rpt->recipient_id->length) {
        if (rcpkey_id.length != 0)
          ok = memcmp(rpt->recipient_id->s, rcpkey_id.s, rcpkey_id.length) != 0;
        if (oscore_r2) {
          if (pt->id_context != NULL && pt->id_context->length > 8) {
            ok = ok + (memcmp(pt->id_context->s, oscore_r2, 8) != 0);
          } else {
            ok += 1;
          }
        } else if (ctxkey_id) {
          if (pt->id_context != NULL) {
            if (ctxkey_id->length != pt->id_context->length)
              ok += 1;
            else
              ok = ok + (memcmp(pt->id_context->s,
                                ctxkey_id->s,
                                ctxkey_id->length) != 0);
          } else if (ctxkey_id->length > 0)
            ok += 1;
        }
        if (ok == 0) {
          /* optional id context and recipient id are the same  */
          *recipient_ctx = rpt;
          return pt; /* OSCORE context found */
        }
      }
      rpt = rpt->next_recipient;
    } /* while rpt */
    pt = pt->next;
  } /* end while */
  return NULL;
}

#define OSCORE_LOG_SIZE 16
void
oscore_log_hex_value(coap_log_t level,
                     const char *name,
                     coap_bin_const_t *value) {
  size_t i;

  if (value == NULL) {
    coap_log(level, "    %-16s\n", name);
    return;
  }
  if (value->length == 0) {
    coap_log(level, "    %-16s <>\n", name);
    return;
  }
  if (coap_get_log_level() >= level) {
    for (i = 0; i < value->length; i += OSCORE_LOG_SIZE) {
      char number[3 * OSCORE_LOG_SIZE + 4];

      oscore_convert_to_hex(&value->s[i],
                            value->length - i > OSCORE_LOG_SIZE
                                ? OSCORE_LOG_SIZE
                                : value->length - i,
                            number,
                            sizeof(number));
      coap_log(level, "    %-16s %s\n", i == 0 ? name : "", number);
    }
  }
}

void
oscore_log_int_value(coap_log_t level, const char *name, int value) {
  coap_log(level, "    %-16s %2d\n", name, value);
}

void
oscore_convert_to_hex(const uint8_t *src,
                      size_t src_len,
                      char *dest,
                      size_t dst_len) {
  /*
   * Last output character will be '\000'
   * (If output undersized, add trailing ... to indicate this.
   */
  size_t space = (dst_len - 4) / 3;
  uint32_t qq;

  for (qq = 0; qq < src_len && qq < space; qq++) {
    char tmp = src[qq] >> 4;
    if (tmp > 9)
      tmp = tmp + 0x61 - 10;
    else
      tmp = tmp + 0x30;
    dest[qq * 3] = tmp;
    tmp = src[qq] & 0xf;
    if (tmp > 9)
      tmp = tmp + 0x61 - 10;
    else
      tmp = tmp + 0x30;
    dest[qq * 3 + 1] = tmp;
    dest[qq * 3 + 2] = 0x20;
  }
  if (qq != src_len) {
    dest[qq * 3] = '.';
    dest[qq * 3 + 1] = '.';
    dest[qq * 3 + 2] = '.';
    qq++;
  }
  dest[qq * 3] = 0;
}

static coap_bin_const_t *
oscore_build_key(oscore_ctx_t *osc_ctx,
                 coap_bin_const_t *id,
                 coap_str_const_t *type,
                 size_t out_len) {
  uint8_t info_buffer[60];
  size_t info_len;
  uint8_t hkdf_tmp[CONTEXT_KEY_LEN > CONTEXT_INIT_VECT_LEN
                       ? CONTEXT_KEY_LEN
                       : CONTEXT_INIT_VECT_LEN];

  info_len = compose_info(info_buffer,
                          sizeof(info_buffer),
                          osc_ctx->aead_alg,
                          id,
                          osc_ctx->id_context,
                          type,
                          out_len);
  if (info_len == 0)
    return NULL;

  oscore_hkdf(osc_ctx->hkdf_alg,
              osc_ctx->master_salt,
              osc_ctx->master_secret,
              info_buffer,
              info_len,
              hkdf_tmp,
              out_len);
  return coap_new_bin_const(hkdf_tmp, out_len);
}

void
oscore_update_ctx(oscore_ctx_t *osc_ctx, coap_bin_const_t *id_context) {
  coap_bin_const_t *temp;

  /* Update with new ID Context */
  coap_delete_bin_const(osc_ctx->id_context);
  osc_ctx->id_context = id_context;

  /* Update sender_key, recipient_key and common_iv */
  temp = osc_ctx->sender_context->sender_key;
  osc_ctx->sender_context->sender_key =
      oscore_build_key(osc_ctx,
                       osc_ctx->sender_context->sender_id,
                       coap_make_str_const("Key"),
                       CONTEXT_KEY_LEN);
  if (!osc_ctx->sender_context->sender_key)
    osc_ctx->sender_context->sender_key = temp;
  else
    coap_delete_bin_const(temp);
  temp = osc_ctx->recipient_chain->recipient_key;
  osc_ctx->recipient_chain->recipient_key =
      oscore_build_key(osc_ctx,
                       osc_ctx->recipient_chain->recipient_id,
                       coap_make_str_const("Key"),
                       CONTEXT_KEY_LEN);
  if (!osc_ctx->recipient_chain->recipient_key)
    osc_ctx->recipient_chain->recipient_key = temp;
  else
    coap_delete_bin_const(temp);
  temp = osc_ctx->common_iv;
  osc_ctx->common_iv = oscore_build_key(osc_ctx,
                                        NULL,
                                        coap_make_str_const("IV"),
                                        CONTEXT_INIT_VECT_LEN);
  if (!osc_ctx->common_iv)
    osc_ctx->common_iv = temp;
  else
    coap_delete_bin_const(temp);
#ifdef HAVE_OSCORE_GROUP
  /* Group Encryption Key */
  temp = osc_ctx->group_enc_key;
  osc_ctx->group_enc_key =
      oscore_build_key(osc_ctx,
                       NULL,
                       coap_make_str_const("Group Encryption Key"),
                       CONTEXT_KEY_LEN);
  if (!osc_ctx->group_enc_key)
    osc_ctx->group_enc_key = temp;
  else
    coap_delete_bin_const(temp);
#endif /* HAVE_OSCORE_GROUP */

  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    coap_log(COAP_LOG_OSCORE, "Updated Common context \n");
    oscore_log_hex_value(COAP_LOG_OSCORE, "ID Context", osc_ctx->id_context);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Master Secret",
                         osc_ctx->master_secret);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Master Salt", osc_ctx->master_salt);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Common IV", osc_ctx->common_iv);
#ifdef HAVE_OSCORE_GROUP
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Group Enc Key",
                         osc_ctx->group_enc_key);
#endif /* HAVE_OSCORE_GROUP */
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sender ID",
                         osc_ctx->sender_context->sender_id);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sender Key",
                         osc_ctx->sender_context->sender_key);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Recipient ID",
                         osc_ctx->recipient_chain->recipient_id);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Recipient Key",
                         osc_ctx->recipient_chain->recipient_key);
  }
}

oscore_ctx_t *
oscore_duplicate_ctx(coap_context_t *c_context,
                     oscore_ctx_t *o_osc_ctx,
                     coap_bin_const_t *sender_id,
                     coap_bin_const_t *recipient_id,
                     coap_bin_const_t *id_context) {
  oscore_ctx_t *osc_ctx = NULL;
  oscore_sender_ctx_t *sender_ctx = NULL;
  coap_bin_const_t *copy_rid = NULL;

  osc_ctx = coap_malloc_type(COAP_OSCORE_COM, sizeof(oscore_ctx_t));
  if (osc_ctx == NULL)
    goto error;
  memset(osc_ctx, 0, sizeof(oscore_ctx_t));

  sender_ctx = coap_malloc_type(COAP_OSCORE_SEN, sizeof(oscore_sender_ctx_t));
  if (sender_ctx == NULL)
    goto error;
  memset(sender_ctx, 0, sizeof(oscore_sender_ctx_t));

  osc_ctx->sender_context = sender_ctx;
  if (o_osc_ctx->master_secret)
    osc_ctx->master_secret =
        coap_new_bin_const(o_osc_ctx->master_secret->s,
                           o_osc_ctx->master_secret->length);
  if (o_osc_ctx->master_salt)
    osc_ctx->master_salt = coap_new_bin_const(o_osc_ctx->master_salt->s,
                                              o_osc_ctx->master_salt->length);
  osc_ctx->aead_alg = o_osc_ctx->aead_alg;
  osc_ctx->hkdf_alg = o_osc_ctx->hkdf_alg;
  if (id_context)
    osc_ctx->id_context = coap_new_bin_const(id_context->s, id_context->length);
#if HAVE_OSCORE_EDHOC
  osc_ctx->edhoc_suite = o_osc_ctx->edhoc_suite;
  osc_ctx->edhoc_suite_cnt = o_osc_ctx->edhoc_suite_cnt;
  osc_ctx->edhoc_method = o_osc_ctx->edhoc_method;
#endif /* !HAVE_OSCORE_EDHOC */
  osc_ctx->ssn_freq = o_osc_ctx->ssn_freq;
  osc_ctx->replay_window_size = o_osc_ctx->replay_window_size;
  osc_ctx->rfc8613_b_1_2 = o_osc_ctx->rfc8613_b_1_2;
  osc_ctx->rfc8613_b_2 = o_osc_ctx->rfc8613_b_2;
  osc_ctx->save_seq_num_func = o_osc_ctx->save_seq_num_func;
  osc_ctx->save_seq_num_func_param = o_osc_ctx->save_seq_num_func_param;
#ifdef HAVE_OSCORE_GROUP
  osc_ctx->mode = o_osc_ctx->mode;
#endif /* HAVE_OSCORE_GROUP */

  if (o_osc_ctx->master_secret) {
    /* sender_ key */
    sender_ctx->sender_key = oscore_build_key(osc_ctx,
                                              sender_id,
                                              coap_make_str_const("Key"),
                                              CONTEXT_KEY_LEN);
    if (!sender_ctx->sender_key)
      goto error;

    /* common IV */
    osc_ctx->common_iv = oscore_build_key(osc_ctx,
                                          NULL,
                                          coap_make_str_const("IV"),
                                          CONTEXT_INIT_VECT_LEN);
    if (!osc_ctx->common_iv)
      goto error;

#ifdef HAVE_OSCORE_GROUP
    /* Group Encryption Key */
    osc_ctx->group_enc_key =
        oscore_build_key(osc_ctx,
                         NULL,
                         coap_make_str_const("Group Encryption Key"),
                         CONTEXT_KEY_LEN);
    if (!osc_ctx->group_enc_key)
      goto error;
#endif /* HAVE_OSCORE_GROUP */
  }

  /*
   * Need to set the last Sender Seq Num based on ssn_freq
   * The value should only change if there is a change to ssn_freq
   * and (potentially) be lower than seq, then save_seq_num_func() is
   * immediately called on next SSN update.
   */
  sender_ctx->next_seq = 0;
  sender_ctx->seq = 0;

  sender_ctx->sender_id = coap_new_bin_const(sender_id->s, sender_id->length);

  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    coap_log(COAP_LOG_OSCORE, "Duplicate Common context \n");
    oscore_log_hex_value(COAP_LOG_OSCORE, "ID Context", osc_ctx->id_context);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Master Secret",
                         osc_ctx->master_secret);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Master Salt", osc_ctx->master_salt);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Common IV", osc_ctx->common_iv);
#ifdef HAVE_OSCORE_GROUP
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Group Enc Key",
                         osc_ctx->group_enc_key);
#endif /* HAVE_OSCORE_GROUP */
    oscore_log_hex_value(COAP_LOG_OSCORE, "Sender ID", sender_ctx->sender_id);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Sender Key", sender_ctx->sender_key);
  }

  copy_rid = coap_new_bin_const(recipient_id->s, recipient_id->length);
  ;
  if (copy_rid == NULL)
    goto error;
  if (oscore_add_recipient(osc_ctx, copy_rid) == NULL)
    goto error;

  oscore_enter_context(c_context, osc_ctx);

  return osc_ctx;

error:
  oscore_free_context(osc_ctx);
  return NULL;
}

oscore_ctx_t *
oscore_derive_ctx(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf) {
  oscore_ctx_t *osc_ctx = NULL;
  oscore_sender_ctx_t *sender_ctx = NULL;

  osc_ctx = coap_malloc_type(COAP_OSCORE_COM, sizeof(oscore_ctx_t));
  if (osc_ctx == NULL)
    goto error;
  memset(osc_ctx, 0, sizeof(oscore_ctx_t));

  sender_ctx = coap_malloc_type(COAP_OSCORE_SEN, sizeof(oscore_sender_ctx_t));
  if (sender_ctx == NULL)
    goto error;
  memset(sender_ctx, 0, sizeof(oscore_sender_ctx_t));

  osc_ctx->sender_context = sender_ctx;
  osc_ctx->master_secret = oscore_conf->master_secret;
  osc_ctx->master_salt = oscore_conf->master_salt;
  osc_ctx->aead_alg = oscore_conf->aead_alg;
  osc_ctx->hkdf_alg = oscore_conf->hkdf_alg;
  osc_ctx->id_context = oscore_conf->id_context;
#if HAVE_OSCORE_EDHOC
  osc_ctx->edhoc_suite = oscore_conf->edhoc_suite;
  osc_ctx->edhoc_suite_cnt = oscore_conf->edhoc_suite_cnt;
  osc_ctx->edhoc_method = oscore_conf->edhoc_method;
#endif /* !HAVE_OSCORE_EDHOC */
  osc_ctx->ssn_freq = oscore_conf->ssn_freq ? oscore_conf->ssn_freq : 1;
  osc_ctx->replay_window_size = oscore_conf->replay_window
                                    ? oscore_conf->replay_window
                                    : COAP_OSCORE_DEFAULT_REPLAY_WINDOW;
  osc_ctx->rfc8613_b_1_2 = oscore_conf->rfc8613_b_1_2;
  osc_ctx->rfc8613_b_2 = oscore_conf->rfc8613_b_2;
  osc_ctx->save_seq_num_func = oscore_conf->save_seq_num_func;
  osc_ctx->save_seq_num_func_param = oscore_conf->save_seq_num_func_param;
#ifdef HAVE_OSCORE_GROUP
  osc_ctx->mode = OSCORE_MODE_SINGLE;
#endif /* HAVE_OSCORE_GROUP */

  if (oscore_conf->master_secret) {
    /* sender_ key */
    sender_ctx->sender_key = oscore_build_key(osc_ctx,
                                              oscore_conf->sender_id,
                                              coap_make_str_const("Key"),
                                              CONTEXT_KEY_LEN);
    if (!sender_ctx->sender_key)
      goto error;

    /* common IV */
    osc_ctx->common_iv = oscore_build_key(osc_ctx,
                                          NULL,
                                          coap_make_str_const("IV"),
                                          CONTEXT_INIT_VECT_LEN);
    if (!osc_ctx->common_iv)
      goto error;

#ifdef HAVE_OSCORE_GROUP
    /* Group Encryption Key */
    osc_ctx->group_enc_key =
        oscore_build_key(osc_ctx,
                         NULL,
                         coap_make_str_const("Group Encryption Key"),
                         CONTEXT_KEY_LEN);
    if (!osc_ctx->group_enc_key)
      goto error;
#endif /* HAVE_OSCORE_GROUP */
  }

  /*
   * Need to set the last Sender Seq Num based on ssn_freq
   * The value should only change if there is a change to ssn_freq
   * and (potentially) be lower than seq, then save_seq_num_func() is
   * immediately called on next SSN update.
   */
  sender_ctx->next_seq = oscore_conf->start_seq_num -
                         (oscore_conf->start_seq_num % oscore_conf->ssn_freq);

  sender_ctx->sender_id = oscore_conf->sender_id;
  sender_ctx->seq = oscore_conf->start_seq_num;

  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    coap_log(COAP_LOG_OSCORE, "Common context \n");
    oscore_log_hex_value(COAP_LOG_OSCORE, "ID Context", osc_ctx->id_context);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Master Secret",
                         osc_ctx->master_secret);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Master Salt", osc_ctx->master_salt);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Common IV", osc_ctx->common_iv);
#ifdef HAVE_OSCORE_GROUP
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Group Enc Key",
                         osc_ctx->group_enc_key);
#endif /* HAVE_OSCORE_GROUP */
    oscore_log_hex_value(COAP_LOG_OSCORE, "Sender ID", sender_ctx->sender_id);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Sender Key", sender_ctx->sender_key);
  }

  if (oscore_add_recipient(osc_ctx, oscore_conf->recipient_id[0]) == NULL)
    goto error;

  oscore_enter_context(c_context, osc_ctx);

  return osc_ctx;

error:
  coap_free_type(COAP_OSCORE_COM, osc_ctx);
  coap_free_type(COAP_OSCORE_SEN, sender_ctx);
  return NULL;
}

oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid) {
  oscore_recipient_ctx_t *rcp_ctx = osc_ctx->recipient_chain;
  oscore_recipient_ctx_t *recipient_ctx = NULL;

  /* Check this is not a duplicate recipient id */
  while (rcp_ctx) {
    if (rcp_ctx->recipient_id->length == rid->length &&
        memcmp(rcp_ctx->recipient_id->s, rid->s, rid->length) == 0) {
      coap_delete_bin_const(rid);
      return 0;
    }
    rcp_ctx = rcp_ctx->next_recipient;
  }
  recipient_ctx = (oscore_recipient_ctx_t *)coap_malloc_type(
      COAP_OSCORE_REC,
      sizeof(oscore_recipient_ctx_t));
  if (recipient_ctx == NULL)
    return NULL;
  memset(recipient_ctx, 0, sizeof(oscore_recipient_ctx_t));

  if (osc_ctx->master_secret) {
    recipient_ctx->recipient_key = oscore_build_key(osc_ctx,
                                                    rid,
                                                    coap_make_str_const("Key"),
                                                    CONTEXT_KEY_LEN);
    if (!recipient_ctx->recipient_key) {
      coap_free_type(COAP_OSCORE_REC, recipient_ctx);
      return NULL;
    }
  }

  recipient_ctx->recipient_id = rid;
  recipient_ctx->initial_state = 1;
  recipient_ctx->osc_ctx = osc_ctx;

  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Recipient ID",
                         recipient_ctx->recipient_id);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Recipient Key",
                         recipient_ctx->recipient_key);
  }

  rcp_ctx = osc_ctx->recipient_chain;
  recipient_ctx->next_recipient = rcp_ctx;
  osc_ctx->recipient_chain = recipient_ctx;
  return recipient_ctx;
}

int
oscore_delete_recipient(oscore_ctx_t *osc_ctx, coap_bin_const_t *rid) {
  oscore_recipient_ctx_t *prev = NULL;
  oscore_recipient_ctx_t *next = osc_ctx->recipient_chain;
  while (next) {
    if (next->recipient_id->length == rid->length &&
        memcmp(next->recipient_id->s, rid->s, rid->length) == 0) {
      if (prev != NULL)
        prev->next_recipient = next->next_recipient;
      else
        osc_ctx->recipient_chain = next->next_recipient;
      oscore_free_recipient(next);
      return 1;
    }
    next = next->next_recipient;
  }
  return 0;
}

void
oscore_free_association(oscore_association_t *association) {
  if (association) {
    coap_delete_bin_const(association->token);
    coap_delete_bin_const(association->aad);
    coap_delete_bin_const(association->nonce);
    coap_delete_bin_const(association->partial_iv);
    coap_free(association);
  }
}

int
oscore_new_association(coap_session_t *session,
                       coap_bin_const_t *token,
                       oscore_recipient_ctx_t *recipient_ctx,
                       coap_bin_const_t *aad,
                       coap_bin_const_t *nonce,
                       coap_bin_const_t *partial_iv,
                       int is_observe) {
  oscore_association_t *association;

  association = coap_malloc(sizeof(oscore_association_t));
  if (association == NULL)
    return 0;

  memset(association, 0, sizeof(oscore_association_t));
  association->recipient_ctx = recipient_ctx;
  association->is_observe = is_observe;

  association->token = coap_new_bin_const(token->s, token->length);
  if (association->token == NULL)
    goto error;

  if (aad) {
    association->aad = coap_new_bin_const(aad->s, aad->length);
    if (association->aad == NULL)
      goto error;
  }

  if (nonce) {
    association->nonce = coap_new_bin_const(nonce->s, nonce->length);
    if (association->nonce == NULL)
      goto error;
  }

  if (partial_iv) {
    association->partial_iv =
        coap_new_bin_const(partial_iv->s, partial_iv->length);
    if (association->partial_iv == NULL)
      goto error;
  }

  OSCORE_ASSOCIATIONS_ADD(session->associations, association);
  return 1;

error:
  oscore_free_association(association);
  return 0;
}

oscore_association_t *
oscore_find_association(coap_session_t *session, coap_bin_const_t *token) {
  oscore_association_t *association;

  OSCORE_ASSOCIATIONS_FIND(session->associations, token, association);
  return association;
}

int
oscore_delete_association(coap_session_t *session,
                          oscore_association_t *association) {
  if (association) {
    OSCORE_ASSOCIATIONS_DELETE(session->associations, association);
    oscore_free_association(association);
    return 1;
  }
  return 0;
}

void
oscore_delete_server_associations(coap_session_t *session) {
  if (session) {
    oscore_association_t *association;
    oscore_association_t *tmp;

    OSCORE_ASSOCIATIONS_ITER_SAFE(session->associations, association, tmp) {
      OSCORE_ASSOCIATIONS_DELETE(session->associations, association);
      oscore_free_association(association);
    }
    session->associations = NULL;
  }
}

#ifdef HAVE_OSCORE_GROUP
#if 0
void
oscore_add_pair_keys(oscore_ctx_t *ctx,
                     oscore_recipient_ctx_t *recipient_ctx,
                     uint8_t *pairwise_recipient_key,
                     uint8_t pairwise_recipient_key_len,
                     uint8_t *pairwise_sender_key,
                     uint8_t pairwise_sender_key_len)
{
  ctx->mode = OSCORE_MODE_PAIRWISE;
  if (pairwise_recipient_key != NULL){
    recipient_ctx->pairwise_recipient_key =
                     coap_new_bin_const(pairwise_recipient_key,
                                        pairwise_recipient_key_len);
  }
  if (pairwise_sender_key != NULL){
    ctx->sender_context->pairwise_sender_key =
                     coap_new_bin_const(pairwise_sender_key,
                                        pairwise_sender_key_len);
  }
  if (coap_get_log_level() >= COAP_LOG_OSCORE){
    oscore_log_hex_value(COAP_LOG_OSCORE, "Sender Pairwise",
                         ctx->sender_context->pairwise_sender_key->key_value);
    oscore_log_hex_value(COAP_LOG_OSCORE, "Recipient Pair",
                         recipient_ctx->pairwise_recipient_key->key_value);
  }
}
#endif

void
oscore_add_group_keys(oscore_ctx_t *ctx,
                      oscore_recipient_ctx_t *recipient_ctx,
                      coap_crypto_pub_key_t *snd_public_key,
                      coap_crypto_pri_key_t *snd_private_key,
                      coap_crypto_pub_key_t *rcp_public_key) {
  if (recipient_ctx == NULL)
    return;

  ctx->mode = OSCORE_MODE_GROUP;

  coap_crypto_delete_private_key(ctx->sender_context->private_key);
  ctx->sender_context->private_key = snd_private_key;
  coap_crypto_delete_public_key(ctx->sender_context->public_key);
  ctx->sender_context->public_key = snd_public_key;

  coap_crypto_delete_public_key(recipient_ctx->public_key);
  recipient_ctx->public_key = rcp_public_key;

  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sender Priv DER",
                         ctx->sender_context->private_key->key_value);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Sender Pub DER",
                         ctx->sender_context->public_key->key_value);
    oscore_log_hex_value(COAP_LOG_OSCORE,
                         "Rcpt Pub DER",
                         recipient_ctx->public_key->key_value);
  }
}

void
oscore_add_group_algorithm(oscore_ctx_t *ctx,
                           cose_alg_t counter_signature_enc_algorithm,
                           cose_alg_t counter_signature_algorithm,
                           uint8_t *counter_signature_parameters,
                           uint8_t counter_signature_parameters_len) {
  ctx->sign_enc_alg = counter_signature_enc_algorithm;
  ctx->sign_alg = counter_signature_algorithm;
  ctx->sign_params = coap_new_bin_const(counter_signature_parameters,
                                        counter_signature_parameters_len);
  if (coap_get_log_level() >= COAP_LOG_OSCORE) {
    oscore_log_hex_value(COAP_LOG_OSCORE, "Sign Params", ctx->sign_params);
  }
}
#endif /* HAVE_OSCORE_GROUP */

int
_strcmp(const char *a, const char *b) {
  if (a == NULL && b != NULL) {
    return -1;
  } else if (a != NULL && b == NULL) {
    return 1;
  } else if (a == NULL && b == NULL) {
    return 0;
  }
  return strcmp(a, b);
}

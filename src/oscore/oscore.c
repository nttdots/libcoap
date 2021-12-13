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
 * @file oscore.c
 * @brief An implementation of the Object Security for Constrained RESTful
 * Enviornments (RFC 8613). \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted to libcoap and major rewrite
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#include "coap3/coap_internal.h"
#include "oscore/oscore.h"
#include "oscore/oscore_context.h"
#include "oscore/oscore_crypto.h"
#include "oscore/oscore_cbor.h"
#include "stdio.h"
#include <stdbool.h>

#define AAD_BUF_LEN 60 /* length of aad_buffer */
#define MAX_IV_LEN  10 /* maximum length of iv buffer */

/* oscore_cs_params
 * returns cbor array [[param_type], [paramtype, param]]
 */
uint8_t *
oscore_cs_params(int8_t param, int8_t param_type, size_t *len) {
  uint8_t buf[50];
  size_t rem_size = sizeof(buf);
  uint8_t *pt = buf;

  *len = 0;
  *len += oscore_cbor_put_array(&pt, &rem_size, 2);
  *len += oscore_cbor_put_array(&pt, &rem_size, 1);
  *len += oscore_cbor_put_number(&pt, &rem_size, param_type);
  *len += oscore_cbor_put_array(&pt, &rem_size, 2);
  *len += oscore_cbor_put_number(&pt, &rem_size, param_type);
  *len += oscore_cbor_put_number(&pt, &rem_size, param);
  uint8_t *result = coap_malloc(*len);
  memcpy(result, buf, *len);
  return result;
}

/* oscore_cs_key_params
 * returns cbor array [paramtype, param]
 */
uint8_t *
oscore_cs_key_params(cose_curve_t param, int8_t param_type, size_t *len) {
  uint8_t buf[50];
  size_t rem_size = sizeof(buf);
  uint8_t *pt = buf;

  *len = 0;
  *len += oscore_cbor_put_array(&pt, &rem_size, 2);
  *len += oscore_cbor_put_number(&pt, &rem_size, param_type);
  *len += oscore_cbor_put_number(&pt, &rem_size, param);
  uint8_t *result = coap_malloc(*len);
  memcpy(result, buf, *len);
  return result;
}

#ifdef HAVE_OSCORE_GROUP
/* extract_param
 * extract algorithm paramater from [type, param]
 */
static int
extract_param(const uint8_t *oscore_cbor_array) {
  int64_t mm = 0;
  uint8_t elem = oscore_cbor_get_next_element(&oscore_cbor_array);
  if (elem == CBOR_ARRAY) {
    uint64_t arr_size = oscore_cbor_get_element_size(&oscore_cbor_array);
    if (arr_size != 2)
      return 0;
    for (uint16_t i = 0; i < arr_size; i++) {
      int8_t ok = oscore_cbor_get_number(&oscore_cbor_array, &mm);
      if (ok != 0)
        return 0;
    }
    return (int)mm;
  }
  return 0;
}

/* extract_type
 * extract algorithm paramater from [type, param]
 */
static int
extract_type(const uint8_t *oscore_cbor_array) {
  int64_t mm = 0;
  uint8_t elem = oscore_cbor_get_next_element(&oscore_cbor_array);
  if (elem == CBOR_ARRAY) {
    uint64_t arr_size = oscore_cbor_get_element_size(&oscore_cbor_array);
    if (arr_size != 2)
      return 0;
    if (oscore_cbor_get_number(&oscore_cbor_array, &mm) == 1)
      return 0;
    return (int)mm;
  }
  return 0;
}
#endif /* HAVE_OSCORE_GROUP */

/*
 * Build the CBOR for external_aad
 *
 * external_aad = bstr .cbor aad_array
 *
 * No group mode
 * aad_array = [
 *   oscore_version : uint,
 *   algorithms : [ alg_aead : int / tstr ],
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr,
 * ]
 *
 * Group mode
 * aad_array = [
 *   oscore_version : uint,
 *   algorithms : [alg_aead : int / tstr / null,
 *                 alg_signature_enc : int / tstr / null,
 *                 alg_signature : int / tstr / null,
 *                 alg_pairwise_key_agreement : int / tstr / null],
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr,
 *   request_kid_context : bstr,
 *   OSCORE_option: bstr,
 *   sender_public_key: bstr,        (initiator's key)
 *   gm_public_key: bstr / null
 * ]
 */
size_t
oscore_prepare_e_aad(oscore_ctx_t *ctx,
                     cose_encrypt0_t *cose,
                     const uint8_t *oscore_option,
                     size_t oscore_option_len,
                     coap_bin_const_t *sender_public_key,
                     uint8_t *external_aad_ptr,
                     size_t external_aad_size) {
  size_t external_aad_len = 0;
  size_t rem_size = external_aad_size;

#ifndef HAVE_OSCORE_GROUP
  (void)oscore_option;
  (void)oscore_option_len;
  (void)sender_public_key;
#endif /* ! HAVE_OSCORE_GROUP */

  if (ctx->mode != OSCORE_MODE_SINGLE)
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 9);
  else
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 5);

  /* oscore_version, always "1" */
  external_aad_len += oscore_cbor_put_unsigned(&external_aad_ptr, &rem_size, 1);

  if (ctx->mode == OSCORE_MODE_SINGLE) {
    /* Algoritms array with one item*/
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 1);
    /* Encryption Algorithm   */
    external_aad_len +=
        oscore_cbor_put_number(&external_aad_ptr, &rem_size, ctx->aead_alg);
  }
#ifdef HAVE_OSCORE_GROUP
  else {
    /* Algoritms array with 4 items */
    external_aad_len += oscore_cbor_put_array(&external_aad_ptr, &rem_size, 4);

    if (ctx->mode == OSCORE_MODE_PAIRWISE) {
      /* alg_aead */
      external_aad_len +=
          oscore_cbor_put_number(&external_aad_ptr, &rem_size, ctx->aead_alg);
      /* alg_signature_enc */
      external_aad_len += oscore_cbor_put_nil(&external_aad_ptr, &rem_size);
      /* alg_signature */
      external_aad_len += oscore_cbor_put_nil(&external_aad_ptr, &rem_size);
      /* alg_pairwise_key_agreement */
      external_aad_len += oscore_cbor_put_number(&external_aad_ptr,
                                                 &rem_size,
                                                 ctx->pairwise_agree_alg);
    } else {
      /* alg_aead */
      external_aad_len += oscore_cbor_put_nil(&external_aad_ptr, &rem_size);
      /* alg_signature_enc */
      external_aad_len += oscore_cbor_put_number(&external_aad_ptr,
                                                 &rem_size,
                                                 ctx->sign_enc_alg);
      /* alg_signature */
      external_aad_len +=
          oscore_cbor_put_number(&external_aad_ptr, &rem_size, ctx->sign_alg);
      /* alg_pairwise_key_agreement */
      external_aad_len += oscore_cbor_put_nil(&external_aad_ptr, &rem_size);
    }
  }
#endif /* HAVE_OSCORE_GROUP */
  /* request_kid */
  external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                            &rem_size,
                                            cose->key_id.s,
                                            cose->key_id.length);
  /* request_piv */
  external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                            &rem_size,
                                            cose->partial_iv.s,
                                            cose->partial_iv.length);
  /* options */
  /* Put integrity protected options, at present there are none. */
  external_aad_len +=
      oscore_cbor_put_bytes(&external_aad_ptr, &rem_size, NULL, 0);

#ifdef HAVE_OSCORE_GROUP
  if (ctx->mode != OSCORE_MODE_SINGLE) {
    /* request_kid_context */
    external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                              &rem_size,
                                              ctx->id_context->s,
                                              ctx->id_context->length);
    /* OSCORE_option */
    external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                              &rem_size,
                                              oscore_option,
                                              oscore_option_len);
    /* sender_public_key */
    external_aad_len += oscore_cbor_put_bytes(&external_aad_ptr,
                                              &rem_size,
                                              sender_public_key->s,
                                              sender_public_key->length);
    /* gm_public_key */
    if (ctx->gm_public_key)
      external_aad_len +=
          oscore_cbor_put_bytes(&external_aad_ptr,
                                &rem_size,
                                ctx->gm_public_key->key_value->s,
                                ctx->gm_public_key->key_value->length);
    else
      external_aad_len += oscore_cbor_put_nil(&external_aad_ptr, &rem_size);
  }
#endif /* HAVE_OSCORE_GROUP */
  return external_aad_len;
}

//
// oscore_encode_option_value
//
size_t
oscore_encode_option_value(uint8_t *option_buffer,
                           cose_encrypt0_t *cose,
                           uint8_t group_flag) {
  size_t offset = 1;

#ifndef HAVE_OSCORE_GROUP
  (void)group_flag;
#endif /* ! HAVE_OSCORE_GROUP */
  if (cose->partial_iv.length > 5) {
    return 0;
  }
#ifdef HAVE_OSCORE_GROUP
  if (group_flag == 1) {
    option_buffer[0] = 0x20;
    cose->group_flag = 1;
  } else
#endif /* HAVE_OSCORE_GROUP */
    option_buffer[0] = 0;

  if (cose->partial_iv.length > 0 && cose->partial_iv.length <= 5 &&
      cose->partial_iv.s != NULL) {
    option_buffer[0] |= (0x07 & cose->partial_iv.length);
    memcpy(&(option_buffer[offset]),
           cose->partial_iv.s,
           cose->partial_iv.length);
    offset += cose->partial_iv.length;
  }

  if (cose->kid_context.length > 0 && cose->kid_context.s != NULL) {
    option_buffer[0] |= 0x10;
    option_buffer[offset] = (uint8_t)cose->kid_context.length;
    offset++;
    memcpy(&(option_buffer[offset]),
           cose->kid_context.s,
           (uint8_t)cose->kid_context.length);
    offset += cose->kid_context.length;
  }

  if (cose->key_id.s != NULL) {
    option_buffer[0] |= 0x08;
    if (cose->key_id.length) {
      memcpy(&(option_buffer[offset]), cose->key_id.s, cose->key_id.length);
      offset += cose->key_id.length;
    }
  }

  if (offset == 1 && option_buffer[0] == 0) {
    /* If option_value is 0x00 it should be empty. */
    offset = 0;
  }
  cose->oscore_option.s = option_buffer;
  cose->oscore_option.length = offset;
  return offset;
}

/*
 * oscore_decode_option_value
 * error: return 0
 * OK: return 1
 *
 * Basic assupmption is that all is preset to 0 or NULL on entry
 */
int
oscore_decode_option_value(const uint8_t *opt_value,
                           size_t option_len,
                           cose_encrypt0_t *cose) {
  uint8_t partial_iv_len = (opt_value[0] & 0x07);
  size_t offset = 1;

  cose->oscore_option.s = opt_value;
  cose->oscore_option.length = option_len;

  if (option_len == 0)
    return 1; /* empty option */

  if (option_len > 255 || partial_iv_len == 6 || partial_iv_len == 7 ||
      (opt_value[0] & 0xC0) != 0) {
    return 0;
  }

  if ((opt_value[0] & 0x20) != 0) {
#ifdef HAVE_OSCORE_GROUP
    cose->group_flag = 1;
  } else {
    cose->group_flag = 0;
#else  /* ! HAVE_OSCORE_GROUP */
    return 0;
#endif /* ! HAVE_OSCORE_GROUP */
  }

  if (partial_iv_len != 0) {
    coap_bin_const_t partial_iv;
    if (offset + partial_iv_len > option_len) {
      return 0;
    }
    partial_iv.s = &(opt_value[offset]);
    partial_iv.length = partial_iv_len;
    cose_encrypt0_set_partial_iv(cose, &partial_iv);
    offset += partial_iv_len;
  }

  if ((opt_value[0] & 0x10) != 0) {
    coap_bin_const_t kid_context;

    kid_context.length = opt_value[offset];
    offset++;
    if (offset + kid_context.length > option_len) {
      return 0;
    }
    kid_context.s = &(opt_value[offset]);
    cose_encrypt0_set_kid_context(cose, &kid_context);
    offset = offset + kid_context.length;
  }

  if ((opt_value[0] & 0x08) != 0) {
    coap_bin_const_t key_id;

    key_id.length = option_len - offset;
    if ((int)key_id.length < 0) {
      return 0;
    }
    key_id.s = &(opt_value[offset]);
    cose_encrypt0_set_key_id(cose, &key_id);
  }
  return 1;
}

#ifdef HAVE_OSCORE_GROUP
/* Sets alg and keys in COSE SIGN  */
void
oscore_populate_sign(cose_sign1_t *sign,
                     oscore_ctx_t *ctx,
                     coap_crypto_pub_key_t *public_key,
                     coap_crypto_pri_key_t *private_key) {
  cose_sign1_set_alg(sign,
                     ctx->sign_alg,
                     extract_param(ctx->sign_params->s),
                     extract_type(ctx->sign_params->s));

  if (private_key)
    cose_sign1_set_private_key(sign, private_key);

  cose_sign1_set_public_key(sign, public_key);
}

//
// oscore_prepare_sig_structure
// creates and sets structure to be signed
size_t
oscore_prepare_sig_structure(uint8_t *sig_ptr,
                             size_t sig_size,
                             const uint8_t *e_aad_buffer,
                             uint16_t e_aad_len,
                             const uint8_t *text,
                             uint16_t text_len) {
  size_t sig_len = 0;
  size_t rem_size = sig_size;
  char countersig0[] = "CounterSignature0";

  (void)sig_size;
  sig_len += oscore_cbor_put_array(&sig_ptr, &rem_size, 5);
  /* 1. "CounterSignature0" */
  sig_len += oscore_cbor_put_text(&sig_ptr,
                                  &rem_size,
                                  countersig0,
                                  strlen(countersig0));
  /* 2. Protected attributes from target structure */
  sig_len += oscore_cbor_put_bytes(&sig_ptr, &rem_size, NULL, 0);
  /* 3. Protected attributes from signer structure */
  sig_len += oscore_cbor_put_bytes(&sig_ptr, &rem_size, NULL, 0);
  /* 4. External AAD */
  sig_len +=
      oscore_cbor_put_bytes(&sig_ptr, &rem_size, e_aad_buffer, e_aad_len);
  /* 5. Payload */
  sig_len += oscore_cbor_put_bytes(&sig_ptr, &rem_size, text, text_len);
  return sig_len;
}
#endif /* HAVE_OSCORE_GROUP */

//
// oscore_prepare_aad
/* Creates and sets External AAD for encryption */
size_t
oscore_prepare_aad(const uint8_t *external_aad_buffer,
                   size_t external_aad_len,
                   uint8_t *aad_buffer,
                   size_t aad_size) {
  size_t ret = 0;
  size_t rem_size = aad_size;
  char encrypt0[] = "Encrypt0";

  (void)aad_size; /* TODO */
  /* Creating the AAD */
  ret += oscore_cbor_put_array(&aad_buffer, &rem_size, 3);
  /* 1. "Encrypt0" */
  ret +=
      oscore_cbor_put_text(&aad_buffer, &rem_size, encrypt0, strlen(encrypt0));
  /* 2. Empty h'' entry */
  ret += oscore_cbor_put_bytes(&aad_buffer, &rem_size, NULL, 0);
  /* 3. External AAD */
  ret += oscore_cbor_put_bytes(&aad_buffer,
                               &rem_size,
                               external_aad_buffer,
                               external_aad_len);

  return ret;
}

//
// oscore_generate_nonce
/* Creates Nonce */
void
oscore_generate_nonce(cose_encrypt0_t *ptr,
                      oscore_ctx_t *ctx,
                      uint8_t *buffer,
                      uint8_t size) {
  memset(buffer, 0, size);
  buffer[0] = (uint8_t)(ptr->key_id.length);
  memcpy(&(buffer[((size - 5) - ptr->key_id.length)]),
         ptr->key_id.s,
         ptr->key_id.length);
  memcpy(&(buffer[size - ptr->partial_iv.length]),
         ptr->partial_iv.s,
         ptr->partial_iv.length);
  for (int i = 0; i < size; i++) {
    buffer[i] = buffer[i] ^ (uint8_t)ctx->common_iv->s[i];
  }
}

//
// oscore_validate_sender_seq
//
/*Return 1 if OK, 0 otherwise */
uint8_t
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose) {
  uint64_t incoming_seq =
      coap_decode_var_bytes8(cose->partial_iv.s, cose->partial_iv.length);

  if (incoming_seq >= OSCORE_SEQ_MAX) {
    coap_log(LOG_WARNING,
             "OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
    return 0;
  }

  ctx->rollback_last_seq = ctx->last_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

  /* Special case since we do not use unisgned int for seq */
  if (ctx->initial_state == 1) {
    ctx->initial_state = 0;
    /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
    ctx->sliding_window = 1;
    ctx->last_seq = incoming_seq;
  } else if (incoming_seq > ctx->last_seq) {
    /* Update the replay window */
    size_t shift = incoming_seq - ctx->last_seq;
    ctx->sliding_window = ctx->sliding_window << shift;
    /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
    ctx->sliding_window |= 1;
    ctx->last_seq = incoming_seq;
  } else if (incoming_seq == ctx->last_seq) {
    coap_log(LOG_WARNING,
             "OSCORE: Replay protextion, replayed SEQ (%lu)\n",
             incoming_seq);
    return 0;
  } else { /* incoming_seq < last_seq */
    size_t shift = ctx->last_seq - incoming_seq - 1;
    uint64_t pattern;

    if (shift > ctx->osc_ctx->replay_window_size || shift > 63) {
      coap_log(
          LOG_WARNING,
          "OSCORE: Replay protection, SEQ outside of replay window (%lu %lu)\n",
          ctx->last_seq,
          incoming_seq);
      return 0;
    }
    /* seq + replay_window_size > last_seq */
    pattern = 1ULL << shift;
    if (ctx->sliding_window & pattern) {
      coap_log(LOG_WARNING,
               "OSCORE: Replay protection, replayed SEQ (%lu)\n",
               incoming_seq);
      return 0;
    }
    /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
    ctx->sliding_window |= pattern;
  }
  coap_log(COAP_LOG_OSCORE,
           "OSCORE: window 0x%lx seq-B0 %lu SEQ %lu\n",
           ctx->sliding_window,
           ctx->last_seq,
           incoming_seq);
  return 1;
}

//
// oscore_increment_sender_seq
//
/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t
oscore_increment_sender_seq(oscore_ctx_t *ctx) {
  ctx->sender_context->seq++;

  if (ctx->sender_context->seq >= OSCORE_SEQ_MAX) {
    return 0;
  } else {
    return 1;
  }
}

//
// oscore_roll_back_seq
/* Restore the sequence number and replay-window to the previous state. This
 * is to be used when decryption fail. */
void
oscore_roll_back_seq(oscore_recipient_ctx_t *ctx) {

  if (ctx->rollback_sliding_window != 0) {
    ctx->sliding_window = ctx->rollback_sliding_window;
    ctx->rollback_sliding_window = 0;
  }
  if (ctx->rollback_last_seq != 0) {
    ctx->last_seq = ctx->rollback_last_seq;
    ctx->rollback_last_seq = 0;
  }
}

/*
 * coap_oscore.c -- Object Security for Constrained RESTful Environments
 *                  (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2021 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore.c
 * @brief CoAP OSCORE handling
 */

#include "coap3/coap_internal.h"

#ifdef HAVE_OSCORE
#include <ctype.h>

#define AAD_BUF_LEN 120      /* length of aad_buffer */

static oscore_ctx_t *
coap_oscore_init(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf);

#ifdef COAP_CLIENT_SUPPORT

int
coap_oscore_initiate(coap_session_t *session,
                     coap_oscore_conf_t *oscore_conf)
{
  if (oscore_conf) {
    oscore_ctx_t *osc_ctx;

#ifdef HAVE_OSCORE_EDHOC
    if (oscore_conf->use_edhoc) {
      edhoc_ctx_t *edhoc_ctx =
                          edhoc_new_context_initiator(session, oscore_conf);

      if (edhoc_ctx == NULL)
        return 0;

      session->doing_first = 1;
      return 1;
    }
#endif /* HAVE_OSCORE_EDHOC */
    if (oscore_conf->recipient_id_count == 0) {
      coap_log(LOG_WARNING,
               "OSCORE: Recipient ID must be defined for a client\n");
      return 0;
    }

    osc_ctx = coap_oscore_init(session->context, oscore_conf);
    if (osc_ctx == NULL) {
      return 0;
    }
    session->recipient_ctx = osc_ctx->recipient_chain;
    session->oscore_encryption = 1;
  }
  return 1;
}

coap_session_t *
coap_new_client_session_oscore(coap_context_t *ctx,
                               const coap_address_t *local_if,
                               const coap_address_t *server,
                               coap_proto_t proto,
                               coap_oscore_conf_t *oscore_conf)
{
  coap_session_t *session = coap_new_client_session(ctx, local_if, server,
                                                    proto);

  if (!session)
    return NULL;

  if (coap_oscore_initiate(session, oscore_conf) == 0) {
    coap_session_release(session);
    return NULL;
  }
  return session;
}

coap_session_t *
coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_cpsk_t *psk_data,
                                   coap_oscore_conf_t *oscore_conf)
{
  coap_session_t *session = coap_new_client_session_psk2(ctx, local_if, server,
                                                       proto, psk_data);

  if (!session)
    return NULL;

  if (coap_oscore_initiate(session, oscore_conf) == 0) {
    coap_session_release(session);
    return NULL;
  }
  return session;
}

coap_session_t *
coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_pki_t *pki_data,
                                   coap_oscore_conf_t *oscore_conf)
{
  coap_session_t *session = coap_new_client_session_pki(ctx, local_if, server,
                                                      proto, pki_data);

  if (!session)
    return NULL;

  if (coap_oscore_initiate(session, oscore_conf) == 0) {
    coap_session_release(session);
    return NULL;
  }
  return session;
}
#endif /* COAP_CLIENT_SUPPORT */
#ifdef COAP_SERVER_SUPPORT

int
coap_context_oscore_server(coap_context_t *context,
                           coap_oscore_conf_t *oscore_conf)
{
#ifdef HAVE_OSCORE_EDHOC
  int use_edhoc = oscore_conf->use_edhoc;
#endif /* HAVE_OSCORE_EDHOC */
  oscore_ctx_t *osc_ctx = coap_oscore_init(context, oscore_conf);

#ifdef HAVE_OSCORE_EDHOC
  if (use_edhoc) {
    if (edhoc_init_resources(context) == 0) {
      return 0;
    }
  }
#endif /* HAVE_OSCORE_EDHOC */
  /* osc_ctx already added to context->osc_ctx */
  if (osc_ctx)
    return 1;
  return 0;
}

#endif /* COAP_SERVER_SUPPORT */

static void
dump_cose(cose_encrypt0_t *cose, const char *message)
{
  if (coap_get_log_level() >= COAP_LOG_CIPHERS) {
    coap_log(COAP_LOG_CIPHERS, "%s Cose information\n", message);
    oscore_log_int_value(COAP_LOG_CIPHERS, "alg", cose->alg);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "key", &cose->key);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "partial_iv", &cose->partial_iv);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "key_id", &cose->key_id);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "kid_context", &cose->kid_context);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "oscore_option", &cose->oscore_option);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "nonce", &cose->nonce);
    oscore_log_hex_value(COAP_LOG_CIPHERS, "aad", &cose->aad);
#ifdef HAVE_OSCORE_GROUP
    oscore_log_int_value(COAP_LOG_CIPHERS, "group_flag", cose->group_flag);
#endif /* HAVE_OSCORE_GROUP */
  }
}

#define MAX_IV_LEN  10      /* maximum length of iv buffer */
/*
 * Take current PDU, create a new one approriately separated as per RFC8613
 * and then encrypt / integrity check the OSCORE data
 */
coap_pdu_t *
coap_oscore_new_pdu_encrypted(coap_session_t *session, coap_pdu_t *pdu,
                              coap_bin_const_t *echo_value, int send_partial_iv)
{
  uint8_t coap_request = COAP_PDU_IS_REQUEST(pdu);
  coap_pdu_code_t code = coap_request ? COAP_REQUEST_CODE_POST :
                                        COAP_RESPONSE_CODE(204);
  coap_pdu_t *osc_pdu;
  coap_pdu_t *plain_pdu = NULL;
  coap_bin_const_t pdu_token;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;
  uint8_t pdu_code = pdu->code;
  size_t length;
  const uint8_t *data;
  uint8_t option_value_buffer[15];
  uint8_t *ciphertext_buffer = NULL;
  size_t ciphertext_len = 0;
  uint8_t aad_buffer[AAD_BUF_LEN];
  uint8_t nonce_buffer[13];
  coap_bin_const_t aad;
  coap_bin_const_t nonce;
  oscore_recipient_ctx_t *rcp_ctx = session->recipient_ctx;
  oscore_ctx_t *osc_ctx = rcp_ctx ? rcp_ctx->common_ctx : NULL;
  cose_encrypt0_t cose[1];
#ifdef HAVE_OSCORE_GROUP
  cose_sign1_t sign[1];
#endif /* HAVE_OSCORE_GROUP */
  uint8_t group_flag = 0;
  coap_uri_t uri;
  int show_pdu = 0;
  int doing_observe = 0;
  uint32_t observe_value = 0;
  oscore_association_t *association = NULL;
  uint8_t partial_iv_buffer[MAX_IV_LEN];
  size_t partial_iv_len;
  oscore_sender_ctx_t *snd_ctx = osc_ctx->sender_context;
  uint8_t external_aad_buffer[100];
  size_t external_aad_len = 0;
  uint8_t oscore_option[20];
  size_t oscore_option_len;

  if (osc_ctx == NULL)
    return NULL;

  /* Check that OSCORE has not already been done */
  if (coap_check_option(pdu, COAP_OPTION_OSCORE, &opt_iter))
    return NULL;

  if (coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter))
    doing_observe = 1;

  coap_show_pdu(LOG_DEBUG, pdu);
  osc_pdu = coap_pdu_init(pdu->type, code, pdu->mid,
                          coap_session_max_pdu_size(session));
  if (osc_pdu == NULL)
    return NULL;

  cose_encrypt0_init(cose);  /* clears cose memory */
  pdu_token = coap_pdu_get_token(pdu);
  if (coap_request) {
    /*
     * RFC8613 8.1 Step 1. Protecting the client's request
     * Get the Sender Context
     */
    rcp_ctx = session->recipient_ctx;
    if (rcp_ctx == NULL)
      goto error;
    osc_ctx = rcp_ctx->common_ctx;
    snd_ctx = osc_ctx->sender_context;
  }
  else {
    /*
     * RFC8613 8.3 Step 1. Protecting the server's response
     * Get the Sender Context
     */
    association = oscore_find_association(session, &pdu_token);
    if (association == NULL)
      goto error;

    rcp_ctx = association->recipient_ctx;
    osc_ctx = rcp_ctx->common_ctx;
    snd_ctx = osc_ctx->sender_context;
    cose_encrypt0_set_partial_iv(cose, association->partial_iv);
    cose_encrypt0_set_aad(cose, association->aad);
  }

#ifdef HAVE_OSCORE_GROUP
  cose_sign1_init(sign); /* clear sign memory */
  if (osc_ctx->mode == OSCORE_MODE_GROUP)
    group_flag = 1;

  if (osc_ctx->mode != OSCORE_MODE_SINGLE && coap_request)
    cose_encrypt0_set_alg(cose, osc_ctx->sign_enc_alg);
  else
#endif /* HAVE_OSCORE_GROUP */
    cose_encrypt0_set_alg(cose, osc_ctx->aead_alg);

  if (coap_request || doing_observe || send_partial_iv) {
    coap_bin_const_t partial_iv;
    partial_iv_len = coap_encode_var_safe8(partial_iv_buffer,
                                           sizeof(partial_iv_buffer),
                                           snd_ctx->seq);
    if (snd_ctx->seq == 0) {
      /* Need to special case */
      partial_iv_buffer[0] = '\000';
      partial_iv_len = 1;
    }
    partial_iv.s = partial_iv_buffer;
    partial_iv.length = partial_iv_len;
    cose_encrypt0_set_partial_iv(cose, &partial_iv);
  }

  cose_encrypt0_set_kid_context(cose, osc_ctx->id_context);

  cose_encrypt0_set_key_id(cose, snd_ctx->sender_id);

  /* nonce (needs to have sender information correctly set up) */

  if (coap_request || doing_observe || send_partial_iv) {
    /*
     *  8.1 Step 3 or RFC8613 8.3.1 Step A
     * Compose the AEAD nonce
     *
     * Requires in COSE object as appropriate
     *   key_id (kid) (sender)
     *   partial_iv   (sender)
     *   common_iv    (already in osc_ctx)
     */
    nonce.s = nonce_buffer;
    nonce.length = 13;
    oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
    cose_encrypt0_set_nonce(cose, &nonce);
    if (!oscore_increment_sender_seq(osc_ctx))
      goto error;
    if (osc_ctx->save_seq_num_func) {
      if (osc_ctx->sender_context->seq > osc_ctx->sender_context->next_seq) {
        /* Only update at ssn_freq rate */
        osc_ctx->sender_context->next_seq += osc_ctx->ssn_freq;
        osc_ctx->save_seq_num_func(osc_ctx->sender_context->next_seq,
                                 osc_ctx->save_seq_num_func_param);
      }
    }
  }
  else {
    /*
     * 8.3 Step 3.
     * Use nonce from request
     */
    cose_encrypt0_set_nonce(cose, association->nonce);
  }

  /* OSCORE_option (needs to be before AAD as included in AAD if group) */

  /* cose is modified for encode option in response message */
  if (!coap_request) {
    /* no kid on response */
    cose_encrypt0_set_key_id(cose, NULL);
    if (!doing_observe && !send_partial_iv)
      cose_encrypt0_set_partial_iv(cose, NULL);
  }
  oscore_option_len = oscore_encode_option_value(oscore_option, cose,
                                                 group_flag);
  if (!coap_request) {
    /* Reset what was just unset as appropriate for AAD */
    cose_encrypt0_set_key_id(cose, rcp_ctx->recipient_id);
    cose_encrypt0_set_partial_iv(cose, association->partial_iv);
  }

  /*
   * RFC8613 8.1/8.3 Step 2(a) (5.4).
   * Compose the External AAD and then AAD
   *
   * OSCORE_option requires
   *  partial_iv                  (cose partial_iv)
   *  kid_context                 (cose kid_context)
   *  key_id                      (cose key_id)
   *  group_flag
   *
   * Non Group (based on osc_tx->mode) requires the following
   *   alg_aead                   (osc_ctx)
   *   request_kid                (request key_id using cose)
   *   request_piv                (request partial_iv using cose)
   *   options                    (none at present)
   * Group (based on osc_tx->mode) requires the following
   *   alg_aead                   (osc_ctx) (pairwise mode)
   *   alg_signature_enc          (osc_ctx) (group mode)
   *   alg_signature              (osc_ctx) (group mode)
   *   alg_pairwise_key_agreement (osc_ctx) (pairwise mode)
   *   request_kid                (request key_id using cose)
   *   request_piv                (request partial_iv using cose)
   *   options                    (none at present)
   *   request_kid_context        (osc_ctx id_context)
   *   OSCORE_option              (parameter)
   *   sender_public_key          (osc_ctx sender_context public_key)
   *   gm_public_key              (osc_ctx gm_public_key)
   *
   * Note: No I options at present
   */


  if (coap_request || osc_ctx->mode != OSCORE_MODE_SINGLE ||
      send_partial_iv) {
    /* External AAD */
    external_aad_len = oscore_prepare_e_aad(osc_ctx, cose,
#ifdef HAVE_OSCORE_GROUP
                                            oscore_option,
                                            oscore_option_len,
                                            osc_ctx->sender_context->public_key,
#else /* HAVE_OSCORE_GROUP */
                                            NULL,
                                            0,
                                            NULL,
#endif /* HAVE_OSCORE_GROUP */
                                            external_aad_buffer,
                                            sizeof(external_aad_buffer));

    /* AAD */
    aad.s = aad_buffer;
    aad.length = oscore_prepare_aad(external_aad_buffer, external_aad_len,
                                    aad_buffer, sizeof(aad_buffer));
    assert(aad.length < AAD_BUF_LEN);
    cose_encrypt0_set_aad(cose, &aad);
  }

  /*
   * RFC8613 8.1/8.3 Step 2(b) (5.3).
   *
   * Set up temp plaintext pdu, the data including token, options and
   * optional payload will get encrypted as COSE ciphertext.
   */
  plain_pdu = coap_pdu_init(pdu->type, pdu->code, pdu->mid,
                          coap_session_max_pdu_size(session));
  if (plain_pdu == NULL)
    goto error;

  coap_add_token(osc_pdu, pdu_token.length, pdu_token.s);

  /* First byte of plain is real CoAP code.  Pretend it is token */
  coap_add_token(plain_pdu, 1, &pdu_code);

  /* Copy across the Outer/Inner Options to respective PDUs */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((option = coap_option_next(&opt_iter))) {
    switch (opt_iter.number) {
    case COAP_OPTION_URI_HOST:
    case COAP_OPTION_URI_PORT:
    case COAP_OPTION_PROXY_SCHEME:
    case COAP_OPTION_HOP_LIMIT:
      /* Outer only */
      if (!coap_insert_option(osc_pdu, opt_iter.number,
                           coap_opt_length(option),
                           coap_opt_value(option)))
        goto error;
      break;
    case COAP_OPTION_OBSERVE:
      /* Make as Outer option as-is */
      if (!coap_insert_option(osc_pdu, opt_iter.number,
                           coap_opt_length(option),
                           coap_opt_value(option)))
        goto error;
      if (coap_request) {
        /* Make as Inner option (unchanged) */
        if (!coap_insert_option(plain_pdu, opt_iter.number,
                                coap_opt_length(option),
                                coap_opt_value(option)))
          goto error;
        osc_pdu->code = COAP_REQUEST_CODE_FETCH;
      }
      else {
        /* Make as Inner option but empty */
        if (!coap_insert_option(plain_pdu, opt_iter.number,
                                0, NULL))
          goto error;
        osc_pdu->code = COAP_RESPONSE_CODE(205);
      }
      show_pdu = 1;
      doing_observe = 1;
      observe_value = coap_decode_var_bytes(coap_opt_value(option),
                                            coap_opt_length(option));
      break;
    case COAP_OPTION_PROXY_URI:
      /* Need to break down into the component parts RFC8613 4.1.3.3 */
      memset(&uri, 0, sizeof(uri));
      if (coap_split_proxy_uri(coap_opt_value(option), coap_opt_length(option),
                               &uri) < 0) {
        coap_log(LOG_WARNING, "Proxy URI '%.*s' not decodable\n",
                 coap_opt_length(option),
                 (const char*)coap_opt_value(option));
        goto error;
      }
      /* Outer options */
      if (!coap_insert_option(osc_pdu, COAP_OPTION_URI_HOST, uri.host.length,
                           uri.host.s))
        goto error;
      if (uri.port != (coap_uri_scheme_is_secure(&uri) ? COAPS_DEFAULT_PORT :
                                                         COAP_DEFAULT_PORT) &&
          !coap_insert_option(osc_pdu, COAP_OPTION_URI_PORT,
                              coap_encode_var_safe(option_value_buffer,
                                                   sizeof(option_value_buffer),
                                                   uri.port & 0xffff),
                              option_value_buffer))
        goto error;
      if (uri.scheme >= COAP_URI_SCHEME_LAST ||
          !coap_insert_option(osc_pdu, COAP_OPTION_PROXY_SCHEME,
                              strlen(coap_uri_scheme[uri.scheme]),
                              (const uint8_t *)coap_uri_scheme[uri.scheme]))
        goto error;
      /* Inner options */
      if (uri.path.length) {
        uint8_t *buf;
        size_t buflen = uri.path.length+1;
        int res;

        buf = coap_malloc(uri.path.length + 1);
        if (buf) {
          res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
          while (res--) {
            if (!coap_insert_option(plain_pdu, COAP_OPTION_URI_PATH,
                coap_opt_length(buf),
                coap_opt_value(buf))) {
              coap_free(buf);
              goto error;
            }
            buf += coap_opt_size(buf);
          }
        }
        coap_free(buf);
      }
      if (uri.query.length) {
         uint8_t *buf;
        size_t buflen = uri.query.length+1;
        int res;

        buf = coap_malloc(uri.query.length + 1);
        if (buf) {
          res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);
          while (res--) {
            if (!coap_insert_option(plain_pdu, COAP_OPTION_URI_QUERY,
                coap_opt_length(buf),
                coap_opt_value(buf))) {
              coap_free(buf);
              goto error;
            }

            buf += coap_opt_size(buf);
          }
          coap_free(buf);
        }
      }
      show_pdu = 1;
      break;
    default:
      /* Make as Inner option */
      if (!coap_insert_option(plain_pdu, opt_iter.number,
                              coap_opt_length(option),
                              coap_opt_value(option)))
        goto error;
      break;
    }
  }
  if (echo_value) {
    /* Add in Inner Echo option response */
    if (!coap_insert_option(plain_pdu, COAP_OPTION_ECHO,
                            echo_value->length,
                            echo_value->s))
      goto error;
    show_pdu = 1;
  }
  /* Add in data to plain */
  if (coap_get_data(pdu, &length, &data)) {
    if (!coap_add_data(plain_pdu, length, data))
      goto error;
  }
  if (show_pdu) {
    coap_log(COAP_LOG_CIPHERS, "OSCORE payload\n");
    coap_show_pdu(COAP_LOG_CIPHERS, plain_pdu);
  }

  /*
   * 8.1/8.3 Step 4.
   * Encrypt the COSE object.
   *
   * Requires in COSE object as appropriate
   *   alg   (already set)
   *   key   (sender key)
   *   nonce (already set)
   *   aad   (already set)
   *   plaintext
   */
  cose_encrypt0_set_key(cose, snd_ctx->sender_key);
  cose_encrypt0_set_plaintext(cose, plain_pdu->token, plain_pdu->used_size);
  dump_cose(cose, "Pre encrypt");
  ciphertext_buffer = coap_malloc_type(COAP_OSCORE_BUF,
                                       OSCORE_CRYPTO_BUFFER_SIZE);
  ciphertext_len = cose_encrypt0_encrypt(cose,
                                         ciphertext_buffer,
                                         plain_pdu->used_size + AES_CCM_TAG);
  assert(ciphertext_len < OSCORE_CRYPTO_BUFFER_SIZE);

#ifdef HAVE_OSCORE_GROUP
  if (osc_ctx->mode != OSCORE_MODE_SINGLE /* && coap_request */) {
    /* sign request message */
    uint8_t *sig_buffer = NULL;
    size_t sig_len = external_aad_len + ciphertext_len + 30;
    int sign_res;
    uint8_t keystream[Ed25519_SIGNATURE_LEN];
    uint8_t *buffer = ciphertext_buffer + ciphertext_len;

    sig_buffer = coap_malloc(sig_len);
    oscore_populate_sign(sign, osc_ctx, snd_ctx->public_key,
                         snd_ctx->private_key);
    sig_len = oscore_prepare_sig_structure(sig_buffer, sig_len,
                                           external_aad_buffer,
                                           external_aad_len,
                                           ciphertext_buffer,
                                           ciphertext_len);
    cose_sign1_set_signature(sign, ciphertext_buffer + ciphertext_len);
    cose_sign1_set_ciphertext(sign, sig_buffer, sig_len);
    sign_res = cose_sign1_sign(sign);
    coap_free(sig_buffer);
    if (sign_res ==0 ){
      coap_log(LOG_WARNING,"OSCORE: Signature Failure \n");
      goto error;
    }
    /* signature at end of encrypted text  */
    ciphertext_len += Ed25519_SIGNATURE_LEN;
    assert(ciphertext_len + Ed25519_SIGNATURE_LEN < OSCORE_CRYPTO_BUFFER_SIZE);

    /* ENC_SIGNATURE = SIGNATURE XOR KEYSTREAM */
    oscore_derive_keystream(osc_ctx, cose, coap_request,
                            snd_ctx->sender_id,
                            osc_ctx->id_context, Ed25519_SIGNATURE_LEN,
                            keystream, sizeof(keystream));
    for(int i = 0; i < Ed25519_SIGNATURE_LEN; i++) {
      buffer[i] = buffer[i] ^ (uint8_t)keystream[i];
    }
  }
#endif /* HAVE_OSCORE_GROUP */

  /* Add in OSCORE option (previously computed) */
  if (!coap_insert_option(osc_pdu, COAP_OPTION_OSCORE, oscore_option_len,
                          oscore_option))
    goto error;

  /* Add now encrypted payload */
  if (!coap_add_data(osc_pdu, ciphertext_len, ciphertext_buffer))
    goto error;

  coap_free_type(COAP_OSCORE_BUF, ciphertext_buffer);
  ciphertext_buffer = NULL;

  coap_delete_pdu(plain_pdu);
  plain_pdu = NULL;

  if (association && association->is_observe == 0)
    oscore_delete_association(session, association);
  association = NULL;

  if (!coap_pdu_encode_header(osc_pdu, session->proto)) {
    goto error;
  }

  /*
   * Set up an association for handling a response if this is a request
   */
  if (coap_request) {
    association = oscore_find_association(session, &pdu_token);
    if (association) {
      if (doing_observe && observe_value == 1) {
        association->is_observe = 0;
      }
      /* Refresh the association */
      coap_delete_bin_const(association->nonce);
      association->nonce = coap_new_bin_const(cose->nonce.s,
                                              cose->nonce.length);
      if (association->nonce == NULL)
        goto error;
      coap_delete_bin_const(association->aad);
      association->aad = coap_new_bin_const(cose->aad.s, cose->aad.length);
      if (association->aad == NULL)
        goto error;
      coap_delete_bin_const(association->partial_iv);
      association->partial_iv = coap_new_bin_const(cose->partial_iv.s,
                                                   cose->partial_iv.length);
      if (association->partial_iv == NULL)
        goto error;
      association->recipient_ctx = rcp_ctx;
    }
    else if (!oscore_new_association(session, &pdu_token,
                                     rcp_ctx, &cose->aad, &cose->nonce,
                                     &cose->partial_iv, doing_observe)) {
      goto error;
    }
  }
  return osc_pdu;

error:
  if (ciphertext_buffer) coap_free_type(COAP_OSCORE_BUF, ciphertext_buffer);
  coap_delete_pdu(osc_pdu);
  coap_delete_pdu(plain_pdu);
  return NULL;
}

static void
build_and_send_error_pdu(coap_session_t *session, coap_pdu_t *rcvd,
                         coap_pdu_code_t code, const char *diagnostic,
                         uint8_t *echo_data, int encrypt_oscore)
{
  coap_pdu_t *err_pdu;
  coap_bin_const_t token;
  int oscore_encryption = session->oscore_encryption;
  coap_mid_t mid = COAP_INVALID_MID;
  unsigned char buf[4];

  err_pdu = coap_pdu_init(rcvd->type == COAP_MESSAGE_NON ?
                                        COAP_MESSAGE_NON : COAP_MESSAGE_ACK,
                          code, rcvd->mid, coap_session_max_pdu_size(session));
  if (!err_pdu)
    return;
  token = coap_pdu_get_token(rcvd);
  coap_add_token(err_pdu, token.length, token.s);
  if (echo_data) {
    coap_add_option_internal(err_pdu, COAP_OPTION_ECHO, 8, echo_data);
  }
  else {
    coap_add_option_internal(err_pdu, COAP_OPTION_MAXAGE,
                             coap_encode_var_safe(buf, sizeof(buf), 0), buf);
  }
  if (diagnostic)
    coap_add_data(err_pdu, strlen(diagnostic),
                  (const uint8_t *)diagnostic);
  session->oscore_encryption = encrypt_oscore;

  if (echo_data && encrypt_oscore) {
    coap_pdu_t *osc_pdu;

    osc_pdu = coap_oscore_new_pdu_encrypted(session, err_pdu, NULL, 1);
    if (!osc_pdu)
      goto fail_resp;
    session->oscore_encryption = 0;
    mid = coap_send_internal(session, osc_pdu);
    coap_delete_pdu(err_pdu);
  }
  else {
    mid = coap_send_internal(session, err_pdu);
  }
fail_resp:
  session->oscore_encryption = oscore_encryption;
  if (mid == COAP_INVALID_MID)
    return;
  return;
}

/* pdu contains incoming message with encrypted COSE ciphertext payload
 * function returns decrypted message
 * and verifies signature, if present
 * returns NULL when decryption,verification fails
 */
coap_pdu_t *
coap_oscore_decrypt_pdu(coap_session_t *session, coap_pdu_t *pdu)
{
  coap_pdu_t *decrypt_pdu = NULL;
  coap_pdu_t *plain_pdu = NULL;
  const uint8_t *osc_value;   /* value of OSCORE option */
  uint8_t osc_size;           /* size of OSCORE OPTION */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL;
#ifdef HAVE_OSCORE_GROUP
  uint8_t group_message = 0;
  cose_sign1_t sign[1];
#endif /* HAVE_OSCORE_GROUP */
  cose_encrypt0_t cose[1];
  oscore_ctx_t *osc_ctx = NULL;
  uint8_t aad_buffer[AAD_BUF_LEN];
  uint8_t nonce_buffer[13];
  coap_bin_const_t aad;
  coap_bin_const_t nonce;
  int pltxt_size = 0;
  uint8_t coap_request = COAP_PDU_IS_REQUEST(pdu);
  coap_bin_const_t pdu_token;
  uint8_t *st_encrypt;
  size_t encrypt_len;
  size_t tag_len;
  oscore_recipient_ctx_t *rcp_ctx = NULL;
  oscore_association_t *association = NULL;
  uint8_t external_aad_buffer[100];
  size_t external_aad_len = 0;
  oscore_sender_ctx_t *snd_ctx = NULL;

  opt = coap_check_option(pdu, COAP_OPTION_OSCORE, &opt_iter);
  assert(opt);
  if (opt == NULL)
    return NULL;

  coap_show_pdu(LOG_DEBUG, pdu);
  if (session->context->osc_ctx == NULL) {
    coap_log(LOG_WARNING,"OSCORE: Not enabled\n");
    return NULL;
  }

  if (pdu->data == NULL) {
    coap_log(LOG_WARNING,"OSCORE: No protected payload\n");
    return NULL;
  }

  osc_size = coap_opt_length(opt);
  osc_value = coap_opt_value(opt);

  cose_encrypt0_init(cose);  /* clear cose memory */
#ifdef HAVE_OSCORE_GROUP
  cose_sign1_init(sign);  /* clear sign memory */
#endif /* HAVE_OSCORE_GROUP */

  /* PDU code will be filled in after decryption */
  decrypt_pdu = coap_pdu_init(pdu->type, 0, pdu->mid,
                              coap_session_max_pdu_size(session));
  if (decrypt_pdu == NULL)
    goto error;

  /* Copy across the Token */
  pdu_token = coap_pdu_get_token(pdu);
  coap_add_token(decrypt_pdu, pdu_token.length, pdu_token.s);

  /*
   * 8.2/8.4 Step 1.
   * Copy outer options across, except E and OSCORE options
   */
  coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
  while ((opt = coap_option_next(&opt_iter))) {
    switch (opt_iter.number) {
    /* 'E' options skipped */
    case COAP_OPTION_IF_MATCH:
    case COAP_OPTION_ETAG:
    case COAP_OPTION_IF_NONE_MATCH:
    case COAP_OPTION_OBSERVE:
    case COAP_OPTION_LOCATION_PATH:
    case COAP_OPTION_URI_PATH:
    case COAP_OPTION_CONTENT_FORMAT:
    case COAP_OPTION_MAXAGE:
    case COAP_OPTION_URI_QUERY:
    case COAP_OPTION_ACCEPT:
    case COAP_OPTION_LOCATION_QUERY:
    case COAP_OPTION_BLOCK2:
    case COAP_OPTION_BLOCK1:
    case COAP_OPTION_SIZE2:
    case COAP_OPTION_SIZE1:
    case COAP_OPTION_NORESPONSE:
    case COAP_OPTION_ECHO:
    case COAP_OPTION_RTAG:
    /* OSCORE does not get copied across */
    case COAP_OPTION_OSCORE:
      break;
    default:
      if (!coap_add_option_internal(decrypt_pdu, opt_iter.number,
                                    coap_opt_length(opt),
                                    coap_opt_value(opt)))
        goto error;
      break;
    }
  }

  if (coap_request) {
    uint64_t incoming_seq;
    coap_bin_const_t empty = { 0,  NULL};
    /*
     * 8.2 Step 2
     * Decompress COSE object
     * Get Recipient Context based on kid and optional kid_context
     */
    if (oscore_decode_option_value(osc_value, osc_size, cose) == 0) {
      coap_log(LOG_WARNING,"OSCORE: OSCORE Option cannot be decoded.\n");
      build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(402),
                               "Failed to decode COSE", NULL, 0);
      goto error_no_ack;
    }
    osc_ctx = oscore_find_context(session->context,
                                  empty,
                                  cose->key_id,
                                  cose->kid_context,
                                  &rcp_ctx);
    if (!osc_ctx) {
      coap_log(LOG_CRIT,"OSCORE: Security Context not found\n");
      build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(401),
                               "Security context not found", NULL, 0);
      goto error_no_ack;
    }
    /* to be used for encryption of returned response later */
    session->recipient_ctx = rcp_ctx;
    snd_ctx = osc_ctx->sender_context;

    /*
     * 8.2 Step 3.
     * Verify Partial IV is not duplicated.
     *
     * Requires in COSE object as appropriate
     *   partial_iv (as received)
     */
    if (rcp_ctx->initial_state == 0 &&
        !oscore_validate_sender_seq(rcp_ctx, cose)) {
      coap_log(LOG_WARNING,"OSCORE: Replayed or old message\n");
      build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(401),
                               "Replay detected", NULL, 0);
      goto error_no_ack;
    }

    incoming_seq = coap_decode_var_bytes8(cose->partial_iv.s,
                                          cose->partial_iv.length);
    rcp_ctx->last_seq = incoming_seq;
  }
  else /* !coap_request */ {
    /*
     * 8.4 Step 2
     * Decompress COSE object
     * Get Recipient Context based on token
     */
    if (oscore_decode_option_value(osc_value, osc_size, cose) == 0) {
      coap_log(LOG_WARNING,"OSCORE: OSCORE Option cannot be decoded.\n");
      goto error;
    }
    association = oscore_find_association(session, &pdu_token);
    if (association) {
      rcp_ctx = association->recipient_ctx;
      osc_ctx = rcp_ctx->common_ctx;
      snd_ctx = osc_ctx->sender_context;
    }
    else {
      coap_log(LOG_CRIT,"OSCORE: Security Context association not found\n");
      goto error;
    }
  }

#ifdef HAVE_OSCORE_GROUP
  group_message = osc_ctx->mode != OSCORE_MODE_SINGLE;
  if ((cose->group_flag == 1 &&
       osc_ctx->mode != OSCORE_MODE_GROUP) ||
      (cose->group_flag == 0 &&
           osc_ctx->mode == OSCORE_MODE_GROUP)) {
    /* mode cannot be treated according to oscore context */
    coap_log(LOG_WARNING,"OSCORE: Unsupported mode\n");
    goto error;
  }

  if (osc_ctx->mode != OSCORE_MODE_SINGLE && coap_request)
    cose_encrypt0_set_alg(cose, osc_ctx->sign_enc_alg);
  else
#endif /* HAVE_OSCORE_GROUP */
    cose_encrypt0_set_alg(cose, osc_ctx->aead_alg);

  if (coap_request) {
    /*
     * RFC8613 8.2 Step 4.
     * Compose the External AAD and then AAD
     *
     * Non Group (based on osc_tx->mode) requires the following
     *   alg_aead                   (osc_ctx)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     * Group (based on osc_tx->mode) requires the following
     *   alg_aead                   (osc_ctx) (pairwise mode)
     *   alg_signature_enc          (osc_ctx) (group mode)
     *   alg_signature              (osc_ctx) (group mode)
     *   alg_pairwise_key_agreement (osc_ctx) (pairwise mode)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     *   request_kid_context        (osc_ctx id_context)
     *   OSCORE_option              (as received in request)
     *   sender_public_key          (recipient public key)
     *   gm_public_key              (osc_ctx gm_public_key)
     *
     * Note: No I options at present
     */

    /* External AAD */
    external_aad_len = oscore_prepare_e_aad(osc_ctx, cose, osc_value,
                                            osc_size,
#ifdef HAVE_OSCORE_GROUP
                                            rcp_ctx->public_key,
#else /* HAVE_OSCORE_GROUP */
                                            NULL,
#endif /* HAVE_OSCORE_GROUP */
                                            external_aad_buffer,
                                            sizeof(external_aad_buffer));

    /* AAD */
    aad.s = aad_buffer;
    aad.length = oscore_prepare_aad(external_aad_buffer, external_aad_len,
                                    aad_buffer, sizeof(aad_buffer));
    assert(aad.length < AAD_BUF_LEN);
    cose_encrypt0_set_aad(cose, &aad);

    /*
     *RFC8613 8.2 Step 5.
     * Compute the AEAD nonce.
     *
     * Requires in COSE object as appropriate
     *   key_id (kid) (Recipient ID)
     *   partial_iv   (as received in request)
     *   common_iv    (already in osc_ctx)
     */
    nonce.s = nonce_buffer;
    nonce.length = 13;
    oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
    cose_encrypt0_set_nonce(cose, &nonce);
    /*
     * Set up an association for use in the response
     */
    association = oscore_find_association(session, &pdu_token);
    if (association) {
      /* Refresh the association */
      coap_delete_bin_const(association->nonce);
      association->nonce = coap_new_bin_const(cose->nonce.s,
                                              cose->nonce.length);
      if (association->nonce == NULL)
        goto error;
      coap_delete_bin_const(association->partial_iv);
      association->partial_iv = coap_new_bin_const(cose->partial_iv.s,
                                                   cose->partial_iv.length);
      if (association->partial_iv == NULL)
        goto error;
      coap_delete_bin_const(association->aad);
      association->aad = coap_new_bin_const(cose->aad.s,
                                            cose->aad.length);
      if (association->aad == NULL)
        goto error;
      association->recipient_ctx = rcp_ctx;
    }
    else if (!oscore_new_association(session, &pdu_token,
                                     rcp_ctx, &cose->aad, &cose->nonce,
                                     &cose->partial_iv, 0)) {
      goto error;
    }
    /* So association is not released when handling decrypt */
    association = NULL;
  }
  else /* ! coap_request */ {
    /* Need to do nonce before AAD because of different partial_iv */
    /*
     * 8.4 Step 4.
     * Compose the AEAD nonce.
     */
    cose_encrypt0_set_key_id(cose, rcp_ctx->recipient_id);
    if (cose->partial_iv.length == 0) {
      cose_encrypt0_set_partial_iv(cose, association->partial_iv);
      cose_encrypt0_set_nonce(cose, association->nonce);
    }
    else {
      /*
       * Requires in COSE object as appropriate
       *   kid (set above)
       *   partial_iv (as received)
       *   common_iv (already in osc_ctx)
       */
      oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
      nonce.s = nonce_buffer;
      nonce.length = 13;
      cose_encrypt0_set_nonce(cose, &nonce);
    }
#ifdef OSCORE_EXTRA_DEBUG
    dump_cose(cose, "!req post nonce");
#endif /* OSCORE_EXTRA_DEBUG */
    /*
     * 8.4 Step 3.
     * Compose the External AAD and then AAD (same as request non-group (5.4)
     *
     * Non Group (based on osc_tx->mode) requires the following
     *   alg_aead                   (osc_ctx)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     * Group (based on osc_tx->mode) requires the following
     *   alg_aead                   (osc_ctx) (pairwise mode)
     *   alg_signature_enc          (osc_ctx) (group mode)
     *   alg_signature              (osc_ctx) (group mode)
     *   alg_pairwise_key_agreement (osc_ctx) (pairwise mode)
     *   request_kid                (request key_id using cose)
     *   request_piv                (request partial_iv using cose)
     *   options                    (none at present)
     *   request_kid_context        (osc_ctx id_context)
     *   OSCORE_option              (as received in request)
     *   sender_public_key          (recipient public key)
     *   gm_public_key              (osc_ctx gm_public_key)
     *
     * Note: No I options at present
     */

    /* External AAD */
    cose_encrypt0_set_key_id(cose, snd_ctx->sender_id);
    cose_encrypt0_set_partial_iv(cose, association->partial_iv);
#ifdef OSCORE_EXTRA_DEBUG
    dump_cose(cose, "!req pre aad");
#endif /* OSCORE_EXTRA_DEBUG */
    external_aad_len = oscore_prepare_e_aad(osc_ctx, cose,
#ifdef HAVE_OSCORE_GROUP
                                            osc_value,
                                            osc_size,
                                            rcp_ctx->public_key,
#else /* HAVE_OSCORE_GROUP */
                                            NULL,
                                            0,
                                            NULL,
#endif /* HAVE_OSCORE_GROUP */
                                            external_aad_buffer,
                                            sizeof(external_aad_buffer));

    /* AAD */
    aad.s = aad_buffer;
    aad.length = oscore_prepare_aad(external_aad_buffer, external_aad_len,
                                    aad_buffer, sizeof(aad_buffer));
    assert(aad.length < AAD_BUF_LEN);
    cose_encrypt0_set_aad(cose, &aad);
#ifdef OSCORE_EXTRA_DEBUG
    dump_cose(cose, "!req pre nonce");
#endif /* OSCORE_EXTRA_DEBUG */
  }

  /*
   * 8.2 Step 6 / 8.4 Step 5.
   * Decrypt the COSE object.
   *
   * Requires in COSE object as appropriate
   *   alg   (already set)
   *   key
   *   nonce (already set)
   *   aad   (already set)
   *   ciphertext
   */
  st_encrypt =  pdu->data;
  encrypt_len = pdu->used_size - (pdu->data - pdu->token);
#ifdef HAVE_OSCORE_GROUP
  if (group_message == 1)
    encrypt_len = encrypt_len - Ed25519_SIGNATURE_LEN;
#endif /* HAVE_OSCORE_GROUP */
  if (encrypt_len <= 0) {
    coap_log(LOG_WARNING,"OSCORE: No protected payload\n");
    goto error;
  }
  cose_encrypt0_set_key(cose, rcp_ctx->recipient_key);
  cose_encrypt0_set_ciphertext(cose, st_encrypt, encrypt_len);

  tag_len = cose_tag_len(cose->alg);
  /* Decrypt into plain_pdu, so code (token), options and data are in place */
  plain_pdu = coap_pdu_init(0, 0, 0, encrypt_len /* - tag_len */);
  if (plain_pdu == NULL)
    goto error;

  /* need the tag_len on the end for TinyDTLS to do its work - yuk */
  if (!coap_pdu_resize(plain_pdu, encrypt_len /* - tag_len */))
    goto error;

  /* Account for 1 byte 'code' used as token */
  plain_pdu->token_length = 1;
  /* Account for the decrypted data */
  plain_pdu->used_size = encrypt_len - tag_len;

#ifdef HAVE_OSCORE_GROUP
  if (group_message == 1) {
    /* verify signature */
    uint8_t *st_signature = st_encrypt + encrypt_len;
    uint8_t *sig_buffer = NULL;
    size_t  sig_len = external_aad_len + encrypt_len + 30;
    int sign_res;
    uint8_t keystream[Ed25519_SIGNATURE_LEN];

    sig_buffer = coap_malloc(sig_len);
    oscore_populate_sign(sign, osc_ctx, rcp_ctx->public_key, NULL);
    sig_len = oscore_prepare_sig_structure(sig_buffer, sig_len,
                 external_aad_buffer, external_aad_len,
                 st_encrypt, encrypt_len);
    assert(external_aad_len + encrypt_len + 30 > sig_len);
    cose_sign1_set_signature(sign, st_signature);
    cose_sign1_set_ciphertext(sign, sig_buffer, sig_len);

    /* SIGNATURE = ENC_SIGNATURE XOR KEYSTREAM */
    oscore_derive_keystream(osc_ctx, cose, coap_request,
                            rcp_ctx->recipient_id,
                            osc_ctx->id_context, Ed25519_SIGNATURE_LEN,
                            keystream, sizeof(keystream));
    for(int i = 0; i < Ed25519_SIGNATURE_LEN; i++) {
      st_signature[i] = st_signature[i] ^ (uint8_t)keystream[i];
    }

    sign_res = cose_sign1_verify(sign);
    coap_free(sig_buffer);
    if (sign_res == 0) {
      coap_log(LOG_WARNING,
          "OSCORE: Signature verification Failure \n");
      build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(400),
                               "Decryption failed", NULL, 0);
      goto error_no_ack;
    }
  }
#endif /* HAVE_OSCORE_GROUP */
  dump_cose(cose, "Pre decrypt");
  pltxt_size = cose_encrypt0_decrypt(cose, plain_pdu->token,
                                     encrypt_len - tag_len);
  if (pltxt_size <= 0) {
    coap_log(LOG_WARNING,"OSCORE: Decryption Failure, result code: %d \n",
             (int)pltxt_size);
    if (coap_request) {
      build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(400),
                               "Decryption failed", NULL, 0);
      oscore_roll_back_seq(rcp_ctx);
      goto error_no_ack;
    }
    goto error;
  }

  assert((size_t)pltxt_size < pdu->alloc_size + pdu->max_hdr_size );

  /* Appendix B.1.2 Trap */
  if (coap_request) {
    if (rcp_ctx->initial_state == 1) {
      opt = coap_check_option(plain_pdu, COAP_OPTION_ECHO, &opt_iter);
      if (opt) {
        /* Verify Client is genuine */
        if (coap_opt_length(opt) == 8 &&
            memcmp(coap_opt_value(opt), rcp_ctx->echo_value, 8) == 0) {
          if (!oscore_validate_sender_seq(rcp_ctx, cose)) {
            coap_log(LOG_WARNING,"OSCORE: Replayed or old message\n");
            build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(401),
                                     "Replay detected", NULL, 0);
            goto error_no_ack;
          }
        }
        else
          goto error;
      }
      else {
        /* RFC 8163 Appendix B.1.2 */
        coap_prng(rcp_ctx->echo_value, sizeof(rcp_ctx->echo_value));
        build_and_send_error_pdu(session, pdu, COAP_RESPONSE_CODE(401),
                                 NULL, rcp_ctx->echo_value, 1);
        goto error_no_ack;
      }
    }
  }

  /*
   * 8.2 Step 7 / 8.4 Step 6.
   * Add decrypted Code, options and payload
   * [OSCORE option not copied across previously]
   */

  /* PDU code is pseudo plain_pdu token */
  decrypt_pdu->code = plain_pdu->token[0];

  /* Copy inner decrypted options across */
  coap_option_iterator_init(plain_pdu, &opt_iter, COAP_OPT_ALL);
  while ((opt = coap_option_next(&opt_iter))) {
    size_t len;
    size_t bias;

    switch (opt_iter.number) {
    case COAP_OPTION_OSCORE:
      break;
    case COAP_OPTION_OBSERVE:
      if (!coap_request) {
        bias = cose->partial_iv.length > 3 ? cose->partial_iv.length - 3 : 0;
        len = cose->partial_iv.length > 3 ? 3 : cose->partial_iv.length;
        /* Make Observe option reflect last 3 bytes of partial_iv */
        if (!coap_add_option_internal(decrypt_pdu, opt_iter.number,
                                      len,
                                      cose->partial_iv.s ?
                                        &cose->partial_iv.s[bias] :
                                        NULL))
          goto error;
        break;
      }
      association = oscore_find_association(session, &pdu_token);
      if (association) {
        association->is_observe = 1;
        association = NULL;
      }
      /* Fall Through */
    default:
      if (!coap_insert_option(decrypt_pdu, opt_iter.number,
                              coap_opt_length(opt),
                              coap_opt_value(opt)))
        goto error;
      break;
    }
  }
  /* Need to copy across any data */
  if (opt_iter.length > 0 && opt_iter.next_option &&
      opt_iter.next_option[0] == COAP_PAYLOAD_START) {
    plain_pdu->data = &opt_iter.next_option[1];
    if (!coap_add_data(decrypt_pdu, plain_pdu->used_size -
                       (plain_pdu->data - plain_pdu->token), plain_pdu->data))
      goto error;
  }
  coap_delete_pdu(plain_pdu);
  plain_pdu = NULL;

  /* Make sure headers are correctly set up */
  if (!coap_pdu_encode_header(decrypt_pdu, session->proto)) {
    goto error;
  }
  if (association && association->is_observe == 0)
    oscore_delete_association(session, association);

  return decrypt_pdu;

error:
  coap_send_ack(session, pdu);
error_no_ack:
  if (association && association->is_observe == 0)
    oscore_delete_association(session, association);
  coap_delete_pdu(decrypt_pdu);
  coap_delete_pdu(plain_pdu);
  return NULL;
}

typedef enum {
  COAP_ENC_ASCII    = 0x01,
  COAP_ENC_HEX      = 0x02,
#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)
  COAP_ENC_FILE_PEM = 0x04,
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC */
  COAP_ENC_INTEGER  = 0x08,
  COAP_ENC_TEXT     = 0x10,
  COAP_ENC_BOOL     = 0x20,
  COAP_ENC_LAST
} coap_oscore_coding_t;

static struct coap_oscore_encoding_t {
  const char *name;
  coap_oscore_coding_t encoding;
} oscore_encoding[] = {
  { "ascii", COAP_ENC_ASCII },
  { "hex", COAP_ENC_HEX },
#ifdef HAVE_OSCORE_GROUP
  { "file_pem", COAP_ENC_FILE_PEM },
#endif /* HAVE_OSCORE_GROUP */
  { "integer", COAP_ENC_INTEGER },
  { "text", COAP_ENC_TEXT },
  { "bool", COAP_ENC_BOOL }
};

typedef struct {
  coap_oscore_coding_t encoding;
  union {
    int value_int;
    coap_bin_const_t *value_bin;
    coap_str_const_t value_str;
  } u;
} oscore_value_t;

static uint8_t
hex2char(char c) {
  assert(isxdigit(c));
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  else
    return c - '0';
}

/*
 * Break up each OSCORE Configuration line entry into the 3 parts which
 * are comma separated
 *
 * keyword,encoding,value
 */
static int
get_split_entry(const char **start, size_t size, coap_str_const_t *keyword,
                oscore_value_t *value)
{
  const char *begin = *start;
  const char *end;
  const char *split;
  size_t i;
#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)
  size_t suffix_len;
  coap_string_t *file_name;
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC*/

retry:
  end = memchr(begin, '\n', size);
  if (end == NULL)
    return 0;

  /* Track beginning of next line */
  *start = end + 1;
  if (end > begin && end[-1] == '\r')
    end--;

  if (begin[0] == '#' || (end - begin) == 0) {
    /* Skip comment / blank line */
    size -= end - begin + 1;
    begin = *start;
    goto retry;
  }

  /* Get in the keyword */
  split = memchr(begin, ',', end - begin);
  if (split == NULL)
    goto bad_entry;

  keyword->s = (const uint8_t *)begin;
  keyword->length = split - begin;

  begin = split + 1;
  if ((end - begin) == 0)
    goto bad_entry;
  /* Get in the encoding */
  split = memchr(begin, ',', end - begin);
  if (split == NULL)
    goto bad_entry;

  for (i = 0; i < COAP_ENC_LAST; i++) {
    if (memcmp(begin, oscore_encoding[i].name, split-begin) == 0) {
      value->encoding = oscore_encoding[i].encoding;
      break;
    }
  }
  if (i == COAP_ENC_LAST)
    goto bad_entry;

  begin = split + 1;
  if ((end - begin) == 0)
    goto bad_entry;
  /* Get in the keyword's value */
  if (begin[0] == '"') {
    split = memchr(&begin[1], '"', end - split - 1);
    if (split == NULL)
      goto bad_entry;
    end = split;
    begin++;
  }
  switch (value->encoding) {
  case COAP_ENC_ASCII:
    value->u.value_bin = coap_new_bin_const((const uint8_t *)begin,
                                            end - begin);
    break;
  case COAP_ENC_HEX:
    /* Parse the hex into binary */
    if ((end - begin) % 2 != 0)
      goto bad_entry;
    coap_binary_t * hex = coap_new_binary((end - begin) / 2);
    for (i = 0; (i < (size_t)(end - begin)) && isxdigit(begin[i]) &&
                isxdigit(begin[i+1]); i+=2) {
      hex->s[i/2] = (hex2char(begin[i]) << 4) + hex2char(begin[i+1]);
    }
    if (i != (size_t)(end - begin))
      goto bad_entry;
    value->u.value_bin = (coap_bin_const_t *)hex;
    break;
#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)
  case COAP_ENC_FILE_PEM:
    /* Need NULL terminated file name */
    file_name = coap_new_string(end - begin);
    if (file_name == NULL)
      goto bad_file;
    memcpy(file_name->s, begin, end - begin);

    coap_binary_t *key = coap_new_binary(32);
    suffix_len = sizeof("_private_key") - 1;
    if (keyword->length > suffix_len) {
      if (memcmp("_private_key", &keyword->s[keyword->length - suffix_len],
                 suffix_len) == 0) {
         if (coap_crypto_read_pem_private_key((const char *)file_name->s,
                                              key->s, &key->length) == 0) {
           coap_delete_binary(key);
           goto bad_file;
         }
         value->u.value_bin = (coap_bin_const_t *)key;
         coap_delete_string(file_name);
         break;
      }
    }
    suffix_len = sizeof("_public_key") - 1;
    if (keyword->length > suffix_len) {
      if (memcmp("_public_key", &keyword->s[keyword->length - suffix_len],
                 suffix_len) == 0) {
         if (coap_crypto_read_pem_public_key((const char *)file_name->s,
                                              key->s, &key->length) == 0) {
           coap_delete_binary(key);
           goto bad_file;
         }
         value->u.value_bin = (coap_bin_const_t *)key;
         coap_delete_string(file_name);
         break;
      }
    }
    goto bad_file;
    break;
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC*/
  case COAP_ENC_INTEGER:
    value->u.value_int = atoi(begin);
    break;
  case COAP_ENC_TEXT:
    value->u.value_str.s = (const uint8_t *)begin;
    value->u.value_str.length = end - begin;
    break;
  case COAP_ENC_BOOL:
    if (memcmp("true", begin, end - begin) == 0)
      value->u.value_int = 1;
    else if (memcmp("false", begin, end - begin) == 0)
      value->u.value_int = 0;
    else
      goto bad_entry;
    break;
  case COAP_ENC_LAST:
  default:
    goto bad_entry;
  }
  return 1;

bad_entry:
  coap_log(LOG_WARNING,
           "oscore_conf: Unrecognized configuration entry '%.*s'\n",
           (int)(end - begin - 1), begin);
  return 0;

#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)
bad_file:
  coap_log(LOG_WARNING,
           "oscore_conf: Bad configuration file_pem entry '%.*s'\n",
           (int)file_name->length, file_name->s);
  coap_delete_string(file_name);
  return 0;
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC*/
}

#undef CONFIG_ENTRY
#define CONFIG_ENTRY(n,e,t) { #n, e, offsetof(coap_oscore_conf_t, n), t }

typedef struct oscore_text_mapping_t {
  const char *text;
  int value;
} oscore_text_mapping_t;

/* Naming as per https://www.iana.org/assignments/cose/cose.xhtml#algorithms */
static oscore_text_mapping_t text_aead_alg[] = {
  { "AES-CCM-16-64-128", COSE_Algorithm_AES_CCM_16_64_128 },
  { "AES-CCM-16-64-256", COSE_Algorithm_AES_CCM_16_64_256 },
  { NULL, 0 }
};

static oscore_text_mapping_t text_hkdf_alg[] = {
  { "HMAC 256/256", COSE_Algorithm_HMAC256_256 },
  { NULL, 0 }
};

static oscore_text_mapping_t text_mode[] = {
  { "single", OSCORE_MODE_SINGLE },
#ifdef HAVE_OSCORE_GROUP
  { "group", OSCORE_MODE_GROUP },
  { "pairwise", OSCORE_MODE_PAIRWISE },
#endif /* HAVE_OSCORE_GROUP */
  { NULL, 0 }
};

#ifdef HAVE_OSCORE_GROUP
static oscore_text_mapping_t text_sign_alg[] = {
  { "EdDSA", COSE_Algorithm_EdDSA },
  { NULL, 0 }
};

static oscore_text_mapping_t text_ecdh_alg[] = {
//  { "ECDH-SS + HKDF-256", COSE_Algorithm_ECDH_SS_HKDF_256 },
  { NULL, 0 }
};
#endif /* HAVE_OSCORE_GROUP */

static struct oscore_config_t {
  const char *keyword;
  coap_oscore_coding_t encoding;
  size_t offset;
  oscore_text_mapping_t *text_mapping;
} oscore_config[] = {
  CONFIG_ENTRY(master_secret, COAP_ENC_HEX | COAP_ENC_ASCII,    NULL),
  CONFIG_ENTRY(master_salt,   COAP_ENC_HEX | COAP_ENC_ASCII,    NULL),
  CONFIG_ENTRY(sender_id,     COAP_ENC_HEX | COAP_ENC_ASCII,    NULL),
  CONFIG_ENTRY(id_context,    COAP_ENC_HEX | COAP_ENC_ASCII,    NULL),
  CONFIG_ENTRY(recipient_id,  COAP_ENC_HEX | COAP_ENC_ASCII,    NULL),
  CONFIG_ENTRY(replay_window, COAP_ENC_INTEGER, NULL),
  CONFIG_ENTRY(ssn_freq,      COAP_ENC_INTEGER, NULL),
  CONFIG_ENTRY(aead_alg,      COAP_ENC_INTEGER | COAP_ENC_TEXT, text_aead_alg),
  CONFIG_ENTRY(hkdf_alg,      COAP_ENC_INTEGER | COAP_ENC_TEXT, text_hkdf_alg),
  CONFIG_ENTRY(mode,          COAP_ENC_TEXT,    text_mode),
  CONFIG_ENTRY(rfc8613_b_2,   COAP_ENC_BOOL,    NULL),
#ifdef HAVE_OSCORE_GROUP
  /* As per draft-ietf-ace-oscore-gm-admin 3.1.1 to provide group support */
  CONFIG_ENTRY(hkdf,          COAP_ENC_INTEGER | COAP_ENC_TEXT, text_hkdf_alg),
/*CONFIG_ENTRY(pub_key_enc,   COAP_ENC_INTEGER, NULL), */
  CONFIG_ENTRY(group_mode,    COAP_ENC_BOOL,    NULL),
  CONFIG_ENTRY(sign_enc_alg,  COAP_ENC_INTEGER | COAP_ENC_TEXT, text_aead_alg),
  CONFIG_ENTRY(sign_alg,      COAP_ENC_INTEGER | COAP_ENC_TEXT, text_sign_alg),
/*CONFIG_ENTRY(sign_params,   COAP_ENC_INTEGER | COAP_ENC_TEXT, text_sign_alg),*/
  CONFIG_ENTRY(pairwise_mode, COAP_ENC_BOOL,    NULL),
  CONFIG_ENTRY(alg,           COAP_ENC_INTEGER | COAP_ENC_TEXT, text_aead_alg),
  CONFIG_ENTRY(ecdh_alg,      COAP_ENC_INTEGER | COAP_ENC_TEXT, text_ecdh_alg),
  CONFIG_ENTRY(gm_public_key,      COAP_ENC_HEX | COAP_ENC_FILE_PEM, NULL),
  CONFIG_ENTRY(recipient_public_key,  COAP_ENC_HEX | COAP_ENC_FILE_PEM, NULL),
#endif /* HAVE_OSCORE_GROUP */

#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)
  CONFIG_ENTRY(sender_public_key,  COAP_ENC_HEX | COAP_ENC_FILE_PEM, NULL),
  CONFIG_ENTRY(sender_private_key, COAP_ENC_HEX | COAP_ENC_FILE_PEM, NULL),
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC */

#ifdef HAVE_OSCORE_EDHOC
  CONFIG_ENTRY(use_edhoc,     COAP_ENC_BOOL, NULL),
  CONFIG_ENTRY(edhoc_method,  COAP_ENC_INTEGER, NULL),
  CONFIG_ENTRY(edhoc_suite,   COAP_ENC_INTEGER, NULL),
  CONFIG_ENTRY(edhoc_alg,     COAP_ENC_INTEGER | COAP_ENC_TEXT, text_aead_alg),
  CONFIG_ENTRY(test_public_key,  COAP_ENC_HEX | COAP_ENC_FILE_PEM, NULL),
  CONFIG_ENTRY(test_private_key, COAP_ENC_HEX | COAP_ENC_FILE_PEM, NULL),
  CONFIG_ENTRY(edhoc_dh_subject, COAP_ENC_ASCII,    NULL),
#endif /* HAVE_OSCORE_EDHOC */
};

int
coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf) {
  uint32_t i;

  if (oscore_conf == NULL)
    return 0;

  coap_delete_bin_const(oscore_conf->master_secret);
  coap_delete_bin_const(oscore_conf->master_salt);
  coap_delete_bin_const(oscore_conf->id_context);
  coap_delete_bin_const(oscore_conf->sender_id);
  for (i = 0; i < oscore_conf->recipient_id_count; i++) {
    coap_delete_bin_const(oscore_conf->recipient_id[i]);
  }
  coap_free(oscore_conf->recipient_id);
#ifdef HAVE_OSCORE_GROUP
  coap_delete_bin_const(oscore_conf->gm_public_key);
  for (i = 0; i < oscore_conf->recipient_public_key_count; i++) {
    coap_delete_bin_const(oscore_conf->recipient_public_key[i]);
  }
  coap_free(oscore_conf->recipient_public_key);
#endif /* HAVE_OSCORE_GROUP */
#if HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC
  coap_delete_bin_const(oscore_conf->sender_public_key);
  coap_delete_bin_const(oscore_conf->sender_private_key);
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC */
#if HAVE_OSCORE_EDHOC
  coap_free(oscore_conf->edhoc_suite);
  coap_delete_bin_const(oscore_conf->test_public_key);
  coap_delete_bin_const(oscore_conf->test_private_key);
  coap_delete_bin_const(oscore_conf->edhoc_dh_subject);
#endif /* HAVE_OSCORE_EDHOC */

  coap_free(oscore_conf);
  return 1;
}

static coap_oscore_conf_t *
coap_parse_oscore_conf_mem(coap_str_const_t conf_mem)
{
  const char *start = (const char *)conf_mem.s;
  const char *end = start + conf_mem.length;
  coap_str_const_t keyword;
  oscore_value_t value;
  coap_oscore_conf_t *oscore_conf;

  oscore_conf = coap_malloc(sizeof(coap_oscore_conf_t));
  if (oscore_conf == NULL)
    return NULL;
  memset(oscore_conf, 0, sizeof(coap_oscore_conf_t));

  memset(&value, 0, sizeof(value));
  /* Preset with defaults */
  oscore_conf->replay_window = COAP_OSCORE_DEFAULT_REPLAY_WINDOW;
  oscore_conf->ssn_freq = 1;
  oscore_conf->aead_alg = COSE_Algorithm_AES_CCM_16_64_128;
  oscore_conf->hkdf_alg = COSE_Algorithm_HMAC256_256;
  oscore_conf->mode = OSCORE_MODE_SINGLE;
#ifdef HAVE_OSCORE_GROUP
  oscore_conf->sign_alg = COSE_Algorithm_EdDSA;
  oscore_conf->sign_enc_alg = COSE_Algorithm_AES_CCM_16_64_128;
#endif /* HAVE_OSCORE_GROUP */

  while (end > start &&
         get_split_entry(&start, end - start, &keyword, &value)) {
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(oscore_config)/sizeof(oscore_config[0]); i++) {
      if (memcmp(oscore_config[i].keyword, keyword.s, keyword.length) == 0 &&
          value.encoding & oscore_config[i].encoding) {
        if (memcmp(keyword.s, "recipient_id", keyword.length) == 0) {
          if (value.u.value_bin->length > 7) {
            coap_log(LOG_WARNING,
                     "oscore_conf: Maximum size of recipient_id is 7 bytes\n");
            goto error_free_value_bin;
          }
          /* Special case as there are potentially multiple entries */
          oscore_conf->recipient_id =
            coap_realloc_type(COAP_STRING, oscore_conf->recipient_id,
                                   sizeof(oscore_conf->recipient_id[0]) *
                                      (oscore_conf->recipient_id_count + 1));
          if (oscore_conf->recipient_id == NULL) {
            goto error_free_value_bin;
          }
          oscore_conf->recipient_id[oscore_conf->recipient_id_count++] =
                                                    value.u.value_bin;
        }
        else if (memcmp(keyword.s, "recipient_public_key",
                        keyword.length) == 0) {
          /* Special case as there are potentially multiple entries */
          oscore_conf->recipient_public_key =
            coap_realloc_type(COAP_STRING, oscore_conf->recipient_public_key,
                              sizeof(oscore_conf->recipient_public_key[0]) *
                                (oscore_conf->recipient_public_key_count + 1));
          if (oscore_conf->recipient_public_key == NULL)
            goto error_free_value_bin;
          oscore_conf->recipient_public_key[oscore_conf->recipient_public_key_count++] =
                                                    value.u.value_bin;
        }
        else if (memcmp(keyword.s, "edhoc_suite",
                        keyword.length) == 0) {
          /* Special case as there are potentially multiple entries */
          oscore_conf->edhoc_suite =
            coap_realloc_type(COAP_STRING, oscore_conf->edhoc_suite,
                              sizeof(oscore_conf->edhoc_suite[0]) *
                                (oscore_conf->edhoc_suite_cnt + 1));
          if (oscore_conf->edhoc_suite == NULL)
            goto error_free_value_bin;
          oscore_conf->edhoc_suite[oscore_conf->edhoc_suite_cnt++] =
                                                    value.u.value_int;
        }
        else {
          coap_bin_const_t *unused_check;

          switch(value.encoding) {
          case COAP_ENC_HEX:
          case COAP_ENC_ASCII:
#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)
          case COAP_ENC_FILE_PEM:
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC*/
            memcpy(&unused_check,
                   &(((char*)oscore_conf)[oscore_config[i].offset]),
                   sizeof(unused_check));
            if (unused_check != NULL) {
              coap_log(LOG_WARNING, "oscore_conf: Keyword '%.*s' duplicated\n",
                       (int)keyword.length, (const char *)keyword.s);
              goto error;
            }
            memcpy(&(((char*)oscore_conf)[oscore_config[i].offset]),
                   &value.u.value_bin, sizeof(value.u.value_bin));
            break;
          case COAP_ENC_INTEGER:
          case COAP_ENC_BOOL:
            memcpy(&(((char*)oscore_conf)[oscore_config[i].offset]),
                   &value.u.value_int, sizeof(value.u.value_int));
            break;
          case COAP_ENC_TEXT:
            for (j = 0; oscore_config[i].text_mapping[j].text != NULL; j++) {
              if (memcmp(value.u.value_str.s,
                         oscore_config[i].text_mapping[j].text,
                         value.u.value_str.length) == 0) {
                memcpy(&(((char*)oscore_conf)[oscore_config[i].offset]),
                       &oscore_config[i].text_mapping[j].value,
                       sizeof(oscore_config[i].text_mapping[j].value));
                break;
              }
            }
            if (oscore_config[i].text_mapping[j].text == NULL) {
              coap_log(LOG_WARNING,
                       "oscore_conf: Keyword '%.*s': value '%.*s' unknown\n",
                       (int)keyword.length, (const char *)keyword.s,
                       (int)value.u.value_str.length,
                       (const char *)value.u.value_str.s);
              goto error;
            }
            break;
          case COAP_ENC_LAST:
          default:
            assert(0);
            break;
          }
        }
        break;
      }
    }
    if (i == sizeof(oscore_config)/sizeof(oscore_config[0])) {
      coap_log(LOG_WARNING, "oscore_conf: Keyword '%.*s', type %d unknown\n",
               (int)keyword.length, (const char *)keyword.s, value.encoding);
      if (value.encoding == COAP_ENC_HEX || value.encoding == COAP_ENC_ASCII)
        coap_delete_bin_const(value.u.value_bin);
      goto error;
    }
  }
  if (oscore_conf->use_edhoc) {
    if (!oscore_conf->recipient_id) {
      coap_log(LOG_WARNING,
               "oscore_conf: use_edhoc: recipient_id not defined\n");
      goto error;
    }
  }
  else {
    if (!oscore_conf->master_secret || !oscore_conf->sender_id ||
        !oscore_conf->recipient_id) {
      coap_log(LOG_WARNING,
               "oscore_conf: One or more of master_secret,"
               " sender_id, recipient_id not defined\n");
      goto error;
    }
    if (oscore_conf->sender_id->length > 7) {
      coap_log(LOG_WARNING,
               "oscore_conf: Maximum size of sender_id is 7 bytes\n");
      goto error;
    }
  }
  if (oscore_conf->recipient_id[0]->length > 7) {
    coap_log(LOG_WARNING,
             "oscore_conf: Maximum size of recipient_id is 7 bytes\n");
    goto error;
  }
#ifdef HAVE_OSCORE_GROUP
  if (oscore_conf->group_mode && (!oscore_conf->id_context ||
      !oscore_conf->sender_public_key || !oscore_conf->sender_private_key ||
      !oscore_conf->recipient_public_key)) {
    coap_log(LOG_WARNING,
             "oscore_conf: group: One or more of id_context,"
             " sender_public_key, sender_private_key and recipient_public_key"
             " not defined\n");
    goto error;
  }
  if (oscore_conf->pairwise_mode && (!oscore_conf->id_context)) {
    coap_log(LOG_WARNING,
             "oscore_conf: group: id_context not defined\n");
    goto error;
  }
#endif /* HAVE_OSCORE_GROUP */
  return oscore_conf;

error_free_value_bin:
  coap_delete_bin_const(value.u.value_bin);
error:
  coap_delete_oscore_conf(oscore_conf);
  return NULL;
}

static oscore_ctx_t *
coap_oscore_init(coap_context_t *c_context, coap_oscore_conf_t *oscore_conf)
{
  oscore_ctx_t *osc_ctx;
  uint32_t i;

  if (!coap_crypto_check_cipher_alg(oscore_conf->aead_alg)) {
    coap_log(LOG_WARNING, "COSE: Cipher Algorithm %d not supported\n",
             oscore_conf->aead_alg);
    goto error;
  }
  if (!coap_crypto_check_hkdf_alg(oscore_conf->hkdf_alg)) {
    coap_log(LOG_WARNING, "COSE: HMAC Algorithm %d not supported\n",
             oscore_conf->hkdf_alg);
    goto error;
  }
#ifdef HAVE_OSCORE_GROUP
  /* TODO Check other algs */
#endif /* HAVE_OSCORE_GROUP */

#ifndef HAVE_OSCORE_GROUP
  if (oscore_conf->mode != OSCORE_MODE_SINGLE) {
    coap_log(LOG_WARNING, "OSCORE: group not enabled\n");
    goto error;
  }
#endif /* !HAVE_OSCORE_GROUP */

#ifdef HAVE_OSCORE_GROUP
  if (oscore_conf->group_mode) {
    /* Set up Group operation */
    if (oscore_conf->recipient_id_count !=
          oscore_conf->recipient_public_key_count) {
      coap_log(LOG_WARNING, "OSCORE: recipient_id count (%d) does not match"
               " recipient_public_key count (%d)\n",
                oscore_conf->recipient_id_count,
                oscore_conf->recipient_public_key_count);
      goto error;
    }
  }
#endif /* HAVE_OSCORE_GROUP */

  osc_ctx = oscore_derive_ctx(oscore_conf->master_secret,
                              oscore_conf->master_salt,
                              oscore_conf->aead_alg,
                              oscore_conf->hkdf_alg,
                              oscore_conf->sender_id,
                              oscore_conf->recipient_id[0],
                              oscore_conf->id_context,
                              oscore_conf->edhoc_suite,
                              oscore_conf->edhoc_suite_cnt,
                              oscore_conf->edhoc_method,
                              oscore_conf->replay_window,
                              oscore_conf->ssn_freq,
                              oscore_conf->save_seq_num_func,
                              oscore_conf->save_seq_num_func_param,
                              oscore_conf->start_seq_num);
  if (!osc_ctx) {
    coap_log(LOG_CRIT, "OSCORE: Could not create Security Context!\n");
    goto error;
  }
  for (i = 1; i < oscore_conf->recipient_id_count; i++) {
    if (oscore_add_recipient(osc_ctx, oscore_conf->recipient_id[i]) == NULL) {
      coap_log(LOG_WARNING, "OSCORE: Failed to add Client ID\n");
      goto error;
    }
  }
  /* Free off the recipient_id array */
  coap_free(oscore_conf->recipient_id);
  oscore_conf->recipient_id = NULL;

#if HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC
  if (oscore_conf->group_mode) {
#if HAVE_OSCORE_GROUP
    oscore_recipient_ctx_t *rcp_ctx = osc_ctx->recipient_chain;

    oscore_add_group_keys(osc_ctx,
                          rcp_ctx,
                          oscore_conf->sender_public_key,
                          oscore_conf->sender_private_key,
                          oscore_conf->recipient_public_key[0]);
    for (i = 1; i < oscore_conf->recipient_public_key_count; i++) {
      /* Add in Client Public Keys */
      rcp_ctx = rcp_ctx->next_recipient;
      if (rcp_ctx) {
        coap_delete_bin_const(rcp_ctx->public_key);
        rcp_ctx->public_key = oscore_conf->recipient_public_key[i];
        if (coap_get_log_level() >= COAP_LOG_CIPHERS) {
          if (rcp_ctx->public_key != NULL)
            oscore_log_hex_value(COAP_LOG_CIPHERS, "Rcpt Pub Key",
                                 rcp_ctx->public_key);
        }
      }
    }
    /* Free off the recipient_public_key array */
    coap_free(oscore_conf->recipient_public_key);

    size_t   counter_signature_parameters_len = 0;
    uint8_t *counter_signature_parameters =
                     oscore_cs_key_params(COSE_curve_Ed25519,
                                          COSE_KTY_OKP,
                                          &counter_signature_parameters_len);
    oscore_add_group_algorithm(osc_ctx,
                               oscore_conf->sign_enc_alg,
                               oscore_conf->sign_alg,
                               counter_signature_parameters,
                               counter_signature_parameters_len);
    coap_free(counter_signature_parameters);
#endif /* HAVE_OSCORE_GROUP */
  }
  else {
    osc_ctx->sender_context->private_key = oscore_conf->sender_private_key;
    osc_ctx->sender_context->public_key = oscore_conf->sender_public_key;
    osc_ctx->sender_context->test_private_key = oscore_conf->test_private_key;
    osc_ctx->sender_context->test_public_key = oscore_conf->test_public_key;
    osc_ctx->sender_context->edhoc_dh_subject = oscore_conf->edhoc_dh_subject;
  }

  if (oscore_conf->pairwise_mode) {
    /* Set up Pairwise operation */
#if 0
    oscore_add_pair_keys(os_ctx,
                     oscore_recipient_ctx_t *rcp_ctx,
                     uint8_t *pairwise_recipient_key,
                     uint8_t pairwise_recipient_key_len,
                     uint8_t *pairwise_sender_key,
                     uint8_t pairwise_sender_key_len)
#endif
  }
#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC */

  /* As all is stored in osc_ctx, oscore_conf is no longer needed */
  coap_free(oscore_conf);

  /* Add to linked chain */
  oscore_enter_context(c_context, osc_ctx);

  /* return default first context  */
  return osc_ctx;

error:
  coap_delete_oscore_conf(oscore_conf);
  return NULL;
}

void
coap_delete_all_oscore(coap_context_t *c_context)
{
  oscore_free_contexts(c_context);
}

void
coap_delete_oscore_associations(coap_session_t *session)
{
  oscore_delete_server_associations(session);
}


coap_oscore_conf_t *
coap_new_oscore_conf(coap_str_const_t conf_mem,
                     coap_oscore_save_seq_num_t save_seq_num_func,
                     void *save_seq_num_func_param,
                     uint64_t start_seq_num)
{
  coap_oscore_conf_t *oscore_conf = coap_parse_oscore_conf_mem(conf_mem);

  if (oscore_conf == NULL)
    return NULL;

  oscore_conf->save_seq_num_func = save_seq_num_func;
  oscore_conf->save_seq_num_func_param = save_seq_num_func_param;
  oscore_conf->start_seq_num = start_seq_num;
  return oscore_conf;
}

/*
 * Compute the size of the potential OSCORE overhead
 */
size_t
coap_oscore_overhead(coap_session_t *session, coap_pdu_t *pdu)
{
  size_t overhead = 0;
  oscore_recipient_ctx_t *rcp_ctx = session->recipient_ctx;
  oscore_ctx_t *osc_ctx = rcp_ctx ? rcp_ctx->common_ctx : NULL;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  if (osc_ctx == NULL)
    return 0;

  /* Protected code held inside */
  overhead += 1;

  /* Observe option (creates inner and outer */
  option = coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter);
  if (option) {
    /* Assume delta is small */
    overhead += 1 + coap_opt_length(option);
  }

  /* Proxy URI option Split */

  /* Echo option */

  /* OSCORE option */
              /* Option header */
  overhead += 1 +
              /* Partial IV (64 bits max)*/
              8 +
              /* kid context */
              (osc_ctx->id_context ? osc_ctx->id_context->length : 0) +
              /* kid */
              osc_ctx->sender_context->sender_id->length;

  /* AAD overhead */
  overhead += AES_CCM_TAG;

  /* Signing Overhead */
#ifdef HAVE_OSCORE_GROUP
  if (osc_ctx && osc_ctx->mode != OSCORE_MODE_SINGLE)
    overhead += Ed25519_SIGNATURE_LEN;
#endif /* HAVE_OSCORE_GROUP */

  /* End of options marker */
  overhead += 1;

  return overhead;
}

int
coap_new_oscore_recipient(coap_context_t *context,
                              coap_bin_const_t *recipient_id)
{
  if (context->osc_ctx == NULL)
    return 0;
  if (oscore_add_recipient(context->osc_ctx, recipient_id) == NULL)
    return 0;
  return 1;
}

int
coap_delete_oscore_recipient(coap_context_t *context,
                                 coap_bin_const_t *recipient_id)
{
  if (context->osc_ctx == NULL)
    return 0;
  return oscore_delete_recipient(context->osc_ctx, recipient_id);
}

/** @} */

#else /* !HAVE_OSCORE */
int
coap_oscore_is_supported(void)
{
  return 0;
}

int
coap_oscore_group_is_supported(void)
{
  return 0;
}

coap_session_t *
coap_new_client_session_oscore(coap_context_t *ctx,
                               const coap_address_t *local_if,
                               const coap_address_t *server,
                               coap_proto_t proto,
                               coap_oscore_conf_t *oscore_conf)
{
  (void)ctx;
  (void)local_if;
  (void)server;
  (void)proto;
  (void)oscore_conf;
  return NULL;
}

coap_session_t *
coap_new_client_session_oscore_psk(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_cpsk_t *psk_data,
                                   coap_oscore_conf_t *oscore_conf)
{
  (void)ctx;
  (void)local_if;
  (void)server;
  (void)proto;
  (void)psk_data;
  (void)oscore_conf;
  return NULL;
}

coap_session_t *
coap_new_client_session_oscore_pki(coap_context_t *ctx,
                                   const coap_address_t *local_if,
                                   const coap_address_t *server,
                                   coap_proto_t proto,
                                   coap_dtls_pki_t *pki_data,
                                   coap_oscore_conf_t *oscore_conf)
{
  (void)ctx;
  (void)local_if;
  (void)server;
  (void)proto;
  (void)pki_data;
  (void)oscore_conf;
  return NULL;
}

int
coap_context_oscore_server(coap_context_t *context,
                           coap_oscore_conf_t *oscore_conf)
{
  (void)context;
  (void)oscore_conf;
  return 0;
}

coap_oscore_conf_t *
coap_new_oscore_conf(coap_str_const_t conf_mem,
                     coap_oscore_save_seq_num_t save_seq_num_func,
                     void *save_seq_num_func_param,
                     uint64_t start_seq_num)
{
  (void)conf_mem;
  (void)save_seq_num_func;
  (void)save_seq_num_func_param;
  (void)start_seq_num;
  return NULL;
}

int
coap_delete_oscore_conf(coap_oscore_conf_t *oscore_conf)
{
  (void)oscore_conf;
  return 0;
}

int
coap_new_oscore_recipient(coap_context_t *context,
                          coap_bin_const_t *recipient_id)
{
  (void)context;
  (void)recipient_id;
  return 0;
}

int
coap_delete_oscore_recipient(coap_context_t *context,
                             coap_bin_const_t *recipient_id)
{
  (void)context;
  (void)recipient_id;
  return 0;
}

#endif /* !HAVE_OSCORE */

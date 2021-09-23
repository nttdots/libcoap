/*
 * coap_oscore_internal.h - Object Security for Constrained RESTful Environments
 *                          (OSCORE) support for libcoap
 *
 * Copyright (C) 2019-2021 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021      Jon Shallow <supjps-libcoap:jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_oscore_internal.h
 * @brief CoAP OSCORE internal information
 */


#ifndef COAP_OSCORE_INTERNAL_H_
#define COAP_OSCORE_INTERNAL_H_

#include "oscore/oscore_context.h"

/**
 * @ingroup internal_api
 * @defgroup oscore_internal OSCORE Support
 * Internal API for interfacing with OSCORE (RFC8613)
 * @{
 */

/**
 * The structure used to hold the configuration information
 */
struct coap_oscore_conf_t {
  coap_bin_const_t *master_secret;/**< Common Master Secret */
  coap_bin_const_t *master_salt;  /**< Common Master Salt */
  coap_bin_const_t *sender_id;    /**< Sender ID (i.e. local our id) */
  coap_bin_const_t *id_context;   /**< Common ID context */
  coap_bin_const_t **recipient_id;/**< Recipient ID (i.e. remote peer id)
                                       Array of recipient_id */
  uint32_t recipient_id_count;    /**< Number of recipient_id entries */
  uint32_t replay_window;         /**< Replay window size
                                       Use COAP_OSCORE_DEFAULT_REPLAY_WINDOW */
  uint32_t ssn_freq;              /**< Sender Seq Num update frequency */
  cose_alg_t aead_alg;            /**< Set to one of COSE_Algorithm_AES* */
  cose_alg_t hkdf_alg;            /**< Set to one of COSE_Algorithm_MHAC* */
  oscore_mode_t mode;             /**< Set to one of OSCORE_MODE_* */
  cose_alg_t hkdf;                /**< Set to one of COSE_Algorithm_HMAC* */
  int rfc8613_b_2;                /**< 1 if rfc8613 B.2 protocol else 0 */

  /* Group */
  int group_mode;                 /**< 1 if group mode else 0 */
  cose_alg_t sign_enc_alg;        /**< Set to one of COSE_Algorithm_AES* */
  cose_alg_t sign_alg;            /**< Set to one of COSE_Algorithm_AES* */
  int pairwise_mode;              /**< 1 if pairwise mode else 0 */
  cose_alg_t alg;                 /**< Set to one of COSE_Algorithm_AES* */
  cose_alg_t ecdh_alg;            /**< Set to one of COSE_Algorithm_AES* */
  coap_bin_const_t *gm_public_key;  /**< Group Manager Public Key */
  coap_bin_const_t **recipient_public_key;  /**< Recipient Public Key (i.e.
                                                 remote peer Key
                                             Array of recipient_public_key */
  uint32_t recipient_public_key_count;  /**< Number of recipient_public_key
                                             entries */
  /* Group and Edhoc */
  coap_bin_const_t *sender_public_key;  /**< Sender Public Key (i.e. local our
                                             Key) */
  coap_bin_const_t *sender_private_key; /**< Private Key for
                                             sender_public_key */

  /* Edhoc */
  int use_edhoc;                    /**< 1 if EDHOC is to be used, else 0 */
  edhoc_method_t edhoc_method;      /**< Method to use for EDHOC */
  int *edhoc_suite;                 /**< Set of valid EDHOC suites */
  uint32_t edhoc_suite_cnt;         /**< Number of EDHOC suite entries */
  cose_alg_t edhoc_alg;             /**< Set to one of COSE_Algorithm_AES* */
  coap_bin_const_t *test_public_key;  /**< Test EDHOC Static DH Public Key */
  coap_bin_const_t *test_private_key; /**< Test EDHOC Static DH Private Key */
  coap_bin_const_t *edhoc_dh_subject; /**< EDHOC Static DH Subject */

  /* SSN handling (not in oscore_config[]) */
  coap_oscore_save_seq_num_t save_seq_num_func; /**< Called every seq num
                                                     change */
  void *save_seq_num_func_param;    /**< Passed to save_seq_num_func() */
  uint64_t start_seq_num;           /**< Used for ssn_freq updating */
};

/**
 * Encrypts the specified @p pdu when OSCORE encryption is required
 * on @p session. This function returns the encrypted PDU or @c NULL
 * on error.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to encrypt if necessary.
 * @param echo_value Optional Echo option to add in or NULL.
 * @param send_partial_iv @c 1 if partial_iv is always to be added, else @c 0
 *                        if not to be added for a response if not required..
 *
 * @return The OSCORE encrypted version of @p pdu, or @c NULL on error.
 */
coap_pdu_t *coap_oscore_new_pdu_encrypted(coap_session_t *session,
                                          coap_pdu_t *pdu,
                                          coap_bin_const_t *echo_value,
                                          int send_partial_iv);

/**
 * Decrypts the OSCORE-encrypted parts of @p pdu when OSCORE is used.
 * This function returns the decrypted PDU or @c NULL on error.
 *
 * @param session The session that will handle the transport of the
 *                specified @p pdu.
 * @param pdu     The PDU to decrypt if necessary.
 *
 * @return The decrypted @p pdu, or @c NULL on error.
 */
struct coap_pdu_t *coap_oscore_decrypt_pdu(coap_session_t *session,
                                           coap_pdu_t *pdu);

/**
 * Cleanup all allocated OSCORE information.
 *
 * @param context The context that the OSCORE information is associated with.
 */
void coap_delete_all_oscore(coap_context_t *context);

/**
 * Cleanup all allocated OSCORE association information.
 *
 * @param session The session that the OSCORE associations are associated with.
 */
void coap_delete_oscore_associations(coap_session_t *session);

/**
 * Determine the additional data size requirements for adding in OSCORE.
 *
 * @param session The session that the OSCORE associations are associated with.
 * @param pdu The non OSCORE protected PDU that is going to be used.
 *
 * @return The OSCORE packet size overhead.
 */
size_t coap_oscore_overhead(coap_session_t *session, coap_pdu_t *pdu);

/**
 * Initiate an OSCORE session
 *
 * @param session The session that the OSCORE associations are associated with.
 * @param oscore_conf The OSCORE configuration.
 *
 * @return @c 1 success, else @c 0 failure.
 */
int
coap_oscore_initiate(coap_session_t *session, coap_oscore_conf_t *oscore_conf);

/** @} */

#endif /* COAP_OSCORE_INTERNAL_H */

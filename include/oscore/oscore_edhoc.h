/*
 * oscore_edhoc.h -- Implementation of EDHOC functionality for libcoap
 *
 * Copyright (C) 2019-2021 Peter van der Stok <consultancy@vanderstok.org>
 * Copyright (C) 2021      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file oscore_edhoc.h
 * @brief CoAP OSCORE EDHOC handling
 */

#ifndef OSCORE_EDHOC_H_
#define OSCORE_EDHOC_H_

#include "oscore/oscore_context.h"

/* define EDHOC states */
typedef enum {
  EDHOC_MESSAGE_1,
  EDHOC_MESSAGE_2,
  EDHOC_MESSAGE_3,
  EDHOC_CONNECTED,
  EDHOC_DONE,
  EDHOC_FAILED
} edhoc_state_t;

/* define EDHOC methods */
typedef enum {
  EDHOC_METHOD_I_SIG_R_SIG = 0,
  EDHOC_METHOD_I_SIG_R_DH = 1,
  EDHOC_METHOD_I_DH_R_SIG = 2,
  EDHOC_METHOD_I_DH_R_DH = 3,
  EDHOC_METHOD_LAST
} edhoc_method_t;

/**
 * Skeletal struct used during EDHOC set up
 */
typedef struct {
  coap_bin_const_t *C_I;
  coap_bin_const_t *C_R;
  coap_bin_const_t *X_private_key;
  coap_bin_const_t *G_X;
  coap_bin_const_t *Y_private_key;
  coap_bin_const_t *G_Y;
  coap_bin_const_t *I_private_key;
  coap_bin_const_t *G_I;
  coap_bin_const_t *R_private_key;
  coap_bin_const_t *G_R;
  coap_bin_const_t *G_XY;
  coap_bin_const_t *dh_subject;
  coap_bin_const_t *ead_1;
  edhoc_state_t state;      /**< EDHOC setup state */
  edhoc_method_t method;    /**< EDHOC method */
  coap_binary_t *message_3; /**< EDHOC message 3 */
  coap_binary_t *message_4; /**< EDHOC message 4 */
  int *suite;               /**< Set of valid EDHOC suites */
  uint32_t suite_cnt;       /**< Number of EDHOC suite entries */
  int selected_suite;       /**< EDHOC Selected suite */
} edhoc_ctx_t;

#if 0
/* stores message2 received for edhoc after message_1 */
int16_t
message_2_receipt(unsigned char *data, size_t len, uint16_t code, uint16_t block_num, uint16_t more);

/* stores message4 received for edhoc after message_1 */
int16_t
edhoc_message_4_receipt(unsigned char *data, size_t len, uint16_t code, uint16_t block_num, uint16_t more);
#endif

int edhoc_init_resources(coap_context_t *ctx);

coap_binary_t *edhoc_oscore_setup(coap_session_t *session);

coap_binary_t *edhoc_create_message_1(edhoc_ctx_t *edhoc_ctx);

coap_binary_t *edhoc_create_message_2(edhoc_ctx_t *edhoc_ctx,
                                      coap_bin_const_t *message_1);

coap_binary_t *edhoc_create_message_3(edhoc_ctx_t *edhoc_ctx,
                                      coap_bin_const_t *message_2);

int16_t edhoc_receive_message_1(edhoc_ctx_t *edhoc_ctx,
                                coap_bin_const_t *message_1);

int16_t edhoc_receive_message_2(edhoc_ctx_t *edhoc_ctx,
                                coap_bin_const_t *message_2);

oscore_ctx_t *edhoc_read_message_4(coap_context_t *ctx,
                                   cose_alg_t hkdf_alg,
                                   coap_string_t *message_1,
                                   coap_string_t *message_2,
                                   coap_string_t *message_3,
                                   coap_string_t *message_4);

edhoc_ctx_t *edhoc_new_context_initiator(coap_session_t *session,
                                         coap_oscore_conf_t *oscore_conf);

edhoc_ctx_t *edhoc_new_context_responder(coap_session_t *session,
                                         oscore_ctx_t *osc_ctx);

void edhoc_delete_context(edhoc_ctx_t *edhoc_ctx);

#endif /* OSCORE_EDHOC_H_  */

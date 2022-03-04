/*
 * coap_asn1_internal.h -- ASN.1 functions for libcoap
 *
 * Copyright (C) 2020 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_asn1_internal.h
 * @brief CoAP ASN.1 internal information
 */

#ifndef COAP_ASN1_INTERNAL_H_
#define COAP_ASN1_INTERNAL_H_

#include "coap_internal.h"

/**
 * @ingroup internal_api
 * @defgroup asn1 ASN.1 Support
 * Internal API for CoAP ASN.1 handling
 * @{
 */

typedef enum {
  COAP_ASN1_NONE = 0,
  COAP_ASN1_INTEGER = 2,
  COAP_ASN1_BITSTRING = 3,
  COAP_ASN1_OCTETSTRING = 4,
  COAP_ASN1_IDENTIFIER = 6,
} coap_asn1_tag_t;

/**
 * Callback to validate the asn1 tag and data.
 *
 * Internal function.
 *
 * @param data  The start of the tag and data
 * @param size  The size of the tag and data
 *
 * @return @c 1 if pass, else @c 0 if fail
 */
typedef int (*asn1_validate)(const uint8_t *data, size_t size);

/**
 * Get the asn1 length from the current @p ptr.
 *
 * Internal function.
 *
 * @param ptr  The current asn.1 object length pointer
 *
 * @return The length of the asn.1 object. @p ptr is updated to be after the length.
 */
size_t asn1_len(const uint8_t **ptr);

/**
 * Get the asn1 tag from the current @p ptr.
 *
 * Internal function.
 *
 * @param ptr  The current asn.1 object tag pointer
 * @param constructed  1 if current tag is constructed
 * @param class  The current class of the tag
 *
 * @return The tag value.@p ptr is updated to be after the tag.
 */
coap_asn1_tag_t asn1_tag_c(const uint8_t **ptr, int *constructed, int *class);

/**
 * Get the asn1 tag and data from the current @p ptr.
 *
 * Internal function.
 *
 * @param ltag The tag to look for
 * @param ptr  The current asn.1 object pointer
 * @param tlen The remaining size oof the asn.1 data
 * @param validate Call validate to verify tag data or @c NULL
 *
 * @return The asn.1 tag and data (to be freed off by caller)
 *         or @c NULL if not found
 */
coap_binary_t *get_asn1_tag(coap_asn1_tag_t ltag, const uint8_t *ptr,
                            size_t tlen, asn1_validate validate);

/**
 * Split the ASN.1 signature into the r and s components.
 *
 * Internal function.
 *
 * @param asn1 The asn.1 to split
 * @param size The size of the split out r and s.
 *
 * @return The combined r + s with leading 0s if needed (to be freed off
 *         by caller) or @c NULL if error.
 */
coap_binary_t *coap_asn1_split_r_s(coap_binary_t *asn1, size_t size);

/**
 * Join the r and s components into ASN1. signature.
 *
 * Internal function.
 *
 * @param r_s The r and s combined to create ASN.1
 *
 * @return The ASN.1 equivalent of r + s (to be freed off
 *         by caller) or @c NULL if error.
 */
coap_binary_t *coap_asn1_r_s_join(coap_binary_t *r_s);

/** @} */

#endif /* COAP_ASN1_INTERNAL_H_ */

/* coap_asn1.c -- ASN.1 handling functions
*
* Copyright (C) 2020 Jon Shallow <supjps-libcoap@jpshallow.com>
*
 * SPDX-License-Identifier: BSD-2-Clause
 *
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

/**
 * @file coap_asn1.c
 * @brief CoAP specific ASN.1 handling
 */

#include "coap3/coap_internal.h"

size_t
asn1_len(const uint8_t **ptr)
{
  size_t len = 0;

  if ((**ptr) & 0x80) {
    size_t octets = (**ptr) & 0x7f;
    (*ptr)++;
    while (octets) {
      len = (len << 8) + (**ptr);
      (*ptr)++;
      octets--;
    }
  }
  else {
    len = (**ptr) & 0x7f;
    (*ptr)++;
  }
  return len;
}

coap_asn1_tag_t
asn1_tag_c(const uint8_t **ptr, int *constructed, int *class)
{
  coap_asn1_tag_t tag = 0;
  uint8_t byte;

  byte = (**ptr);
  *constructed = (byte & 0x20) ? 1 : 0;
  *class = byte >> 6;
  tag = byte & 0x1F;
  (*ptr)++;
  if (tag < 0x1F)
    return tag;

  /* Tag can be one byte or more based on B8 */
  byte = (**ptr);
  while (byte & 0x80) {
    tag = (tag << 7) + (byte & 0x7F);
    (*ptr)++;
    byte = (**ptr);
  }
  /* Do the final one */
  tag = (tag << 7) + (byte & 0x7F);
  (*ptr)++;
  return tag;
}

/* caller must free off returned coap_binary_t* */
coap_binary_t *
get_asn1_tag(coap_asn1_tag_t ltag, const uint8_t *ptr, size_t tlen,
             asn1_validate validate)
{
  int constructed;
  int class;
  const uint8_t *acp = ptr;
  uint8_t tag = asn1_tag_c(&acp, &constructed, &class);
  size_t len = asn1_len(&acp);
  coap_binary_t *tag_data;

  while (tlen > 0 && len <= tlen) {
    if (class == 2 && constructed == 1) {
      /* Skip over element description */
      tag = asn1_tag_c(&acp, &constructed, &class);
      len = asn1_len(&acp);
    }
    if (tag == ltag) {
      if (!validate || validate(acp, len)) {
        tag_data = coap_new_binary(len);
        if (tag_data == NULL)
          return NULL;
        tag_data->length = len;
        memcpy(tag_data->s, acp, len);
        return tag_data;
      }
    }
    if (tag == 0x10 && constructed == 1) {
      /* SEQUENCE or SEQUENCE OF */
      tag_data = get_asn1_tag(ltag, acp, len, validate);
      if (tag_data)
        return tag_data;
    }
    acp += len;
    tlen -= len;
    tag = asn1_tag_c(&acp, &constructed, &class);
    len = asn1_len(&acp);
  }
  return NULL;
}

coap_binary_t *
coap_asn1_split_r_s(coap_binary_t *asn1, size_t size)
{
  int constructed;
  int class;
  const uint8_t *acp = asn1->s;
  uint8_t tag;
  size_t len;
  coap_binary_t *sign;

  if (asn1->s[0] != 0x30)
    return NULL;
  
  tag = asn1_tag_c(&acp, &constructed, &class);
  len = asn1_len(&acp);

  tag = asn1_tag_c(&acp, &constructed, &class);
  len = asn1_len(&acp);
  if (tag != COAP_ASN1_INTEGER)
    return NULL;
  sign = coap_new_binary(size);
  if (sign == NULL)
    return NULL;
  if (len < size/2) {
    /* pad with leading 0s */
    memset(&sign->s[0], 0, size/2 - len);
    memcpy(&sign->s[size/2 - len], acp, len);
  } else {
    /* drop leading 0s if needed */
    memcpy(&sign->s[0], acp + len - size/2, len);
  }

  acp += len;
  tag = asn1_tag_c(&acp, &constructed, &class);
  len = asn1_len(&acp);
  if (tag != COAP_ASN1_INTEGER) {
    coap_delete_binary(sign);
    return NULL;
  }
  if (len < size/2) {
    /* pad with leading 0s */
    memset(&sign->s[size/2], 0, size/2 - len);
    memcpy(&sign->s[size/2 + size/2 - len], acp, len);
  } else {
    /* drop leading 0s if needed */
    memcpy(&sign->s[size/2], acp + len - size/2, len);
  }
  return sign;
}

static void
asn1_add_integer(u_char **cp, u_char *integer, size_t int_len)
{
  size_t i;

  *((*cp)++) = COAP_ASN1_INTEGER;
  if (integer[0] & 0x80) {
    *((*cp)++) = int_len + 1;
    *((*cp)++) = 0x00;
    i = 0;
  } else {
    /* drop leading 0s if needed */
    for (i = 0; i < int_len - 1; i++) {
      if (integer[i] != 0)
        break;
    }
    *((*cp)++) = int_len - i;
  }
  memcpy(*cp, &integer[i], int_len - i);
  *cp += int_len - i;
}

coap_binary_t *
coap_asn1_r_s_join(coap_binary_t *r_s)
{
  coap_binary_t *sign = coap_new_binary(r_s->length + 8);
  u_char *cp;

  if (sign == NULL)
    return NULL;

  cp = sign->s;
  *(cp++) = 0x30; /* SEQUENCE */
  *(cp++) = 0x00; /* Length - to be filled in later */

  asn1_add_integer(&cp, r_s->s, r_s->length/2);

  asn1_add_integer(&cp, &r_s->s[r_s->length/2], r_s->length/2);

  sign->s[1] = cp - sign->s - 2;
  sign->length = cp - sign->s;
  return sign;
}


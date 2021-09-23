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
 * @file oscore_cose.c
 * @brief An implementation of the CBOR Object Signing and Encryption (RFC).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * added sign1 addition for coaplib
 *      Peter van der Stok <consultancy@vanderstok.org >
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 */

#include "coap3/coap_internal.h"
#include "stdio.h"
#include "oscore/oscore_cose.h"
#include "oscore/oscore_cbor.h"
#include "oscore/oscore_crypto.h"
#include "oscore/oscore_context.h"

/* return tag length belonging to cose algorithm */
int
cose_tag_len(int cose_alg){
         switch (cose_alg){
       case COSE_Algorithm_AES_CCM_16_64_128:
         return COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_64_128:
         return COSE_algorithm_AES_CCM_64_64_128_TAG_LEN;
         break;
       case COSE_Algorithm_AES_CCM_16_128_128:
         return COSE_algorithm_AES_CCM_16_128_128_TAG_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_128_128:
         return COSE_algorithm_AES_CCM_64_128_128_TAG_LEN;
         break;
       default:
         return 0;
         break;
         }
}


/* return hash length belonging to cose algorithm */
int
cose_hash_len(int cose_alg){
  switch (cose_alg){
  case COSE_Algorithm_ES256:
    return   COSE_Algorithm_HMAC256_256_HASH_LEN;
  case COSE_Algorithm_ES512:
    return   COSE_ALGORITHM_ES512_HASH_LEN;
  case COSE_Algorithm_ES384:
    return   COSE_ALGORITHM_ES384_HASH_LEN;
  case COSE_Algorithm_HMAC256_64:
    return   COSE_Algorithm_HMAC256_64_HASH_LEN;
  case COSE_Algorithm_HMAC256_256:
    return   COSE_Algorithm_HMAC256_256_HASH_LEN;
  case COSE_Algorithm_HMAC384_384:
    return   COSE_Algorithm_HMAC384_384_HASH_LEN;
  case COSE_Algorithm_HMAC512_512:
    return   COSE_Algorithm_HMAC512_512_HASH_LEN;
   case COSE_Algorithm_SHA_256_64:
    return   COSE_ALGORITHM_SHA_256_64_LEN;
  case COSE_Algorithm_SHA_256_256:
    return   COSE_ALGORITHM_SHA_256_256_LEN;
  case COSE_Algorithm_SHA_512_256:
    return   COSE_ALGORITHM_SHA_512_256_LEN;
  default:
    return 0;
  }
}

/* return nonce length belonging to cose algorithm */
int
cose_nonce_len(int cose_alg){
  switch (cose_alg){
  case COSE_Algorithm_AES_CCM_16_64_128:
    return COSE_algorithm_AES_CCM_16_64_128_IV_LEN;
  case COSE_Algorithm_AES_CCM_64_64_128:
    return COSE_algorithm_AES_CCM_64_64_128_IV_LEN;
  case COSE_Algorithm_AES_CCM_16_128_128:
    return COSE_algorithm_AES_CCM_16_128_128_IV_LEN;
  case COSE_Algorithm_AES_CCM_64_128_128:
    return COSE_algorithm_AES_CCM_64_128_128_IV_LEN;
  default:
    return 0;
  }
}

/* return key length belonging to cose algorithm */
int
cose_key_len(int cose_alg){
  switch (cose_alg){
  case COSE_Algorithm_AES_CCM_16_64_128:
    return COSE_algorithm_AES_CCM_16_64_128_KEY_LEN;
  case COSE_Algorithm_AES_CCM_64_64_128:
    return COSE_algorithm_AES_CCM_64_64_128_KEY_LEN;
  case COSE_Algorithm_AES_CCM_16_128_128:
    return COSE_algorithm_AES_CCM_16_128_128_KEY_LEN;
  case COSE_Algorithm_AES_CCM_64_128_128:
    return COSE_algorithm_AES_CCM_64_128_128_KEY_LEN;
  default:
    return 0;
  }
}

struct CWT_tag_t{
  int16_t     tag_value;
  const char *tag_name;
};

#define NR_OF_TAGS 36
static struct CWT_tag_t cwt_tags[NR_OF_TAGS] =
/* oscore_context tags */
{
{OSCORE_CONTEXT_MS,"ms"},
{OSCORE_CONTEXT_CLIENTID,"clientId"},
{OSCORE_CONTEXT_SERVERID,"serverId"},
{OSCORE_CONTEXT_HKDF,"hkdf"},
{OSCORE_CONTEXT_ALG,"alg"},
{OSCORE_CONTEXT_SALT,"salt"},
{OSCORE_CONTEXT_CONTEXTID,"contextId"},
{OSCORE_CONTEXT_RPL,"rpl"},
{OSCORE_CONTEXT_CSALG, "cs_alg"},
{OSCORE_CONTEXT_CSPARAMS, "cs_params"},
{OSCORE_CONTEXT_CSKEYPARAMS, "cs_key_params"},

/*  CWT - cnf tag  */
{CWT_OSCORE_SECURITY_CONTEXT,"OSCORE_Security_Context"},
{CWT_KEY_COSE_KEY,"COSE_Key"},
{CWT_KEY_ENCRYPTED_COSE_KEY,"Encrypted_COSE_Key"},
{CWT_KEY_KID,"CWT_kid"},

/* CWT tags */
{CWT_CLAIM_ISS,"iss"},
{CWT_CLAIM_SUB,"sub"},
{CWT_CLAIM_AUD,"aud"},
{CWT_CLAIM_EXP,"exp"},
{CWT_CLAIM_NBF,"nbf"},
{CWT_CLAIM_IAT,"iat"},
{CWT_CLAIM_CTI,"cti"},
{CWT_CLAIM_CNF,"cnf"},
{CWT_KEY_KID,"kid"},
/* OAUTH-AUTHZ claims   */
{CWT_CLAIM_SCOPE,"scope"},
{CWT_CLAIM_PROFILE,"profile"},
{CWT_CLAIM_CNONCE,"cnonce"},
{OAUTH_CLAIM_GRANTTYPE, "grant_type"},
{OAUTH_CLAIM_REQCNF, "req_cnf"},
{OAUTH_CLAIM_ACCESSTOKEN, "access_token"},
{OAUTH_CLAIM_RSCNF, "rs_cnf"},
{OAUTH_CLAIM_KEYINFO, "key_info"},
/* group-comm tags*/
{COSE_KCP_KTY, "kty"},
{COSE_KTP_CRV,"crv"},
{COSE_KCP_KEYOPS, "key_ops"},
{COSE_KCP_BASE_IV, "iv"},
};

//  cose_get_tag
//  returns tag value from ACE defined CBOR array of maps
int16_t
cose_get_tag(const uint8_t **data)
{
  uint8_t elem = oscore_cbor_get_next_element(data);
  if (elem == CBOR_UNSIGNED_INTEGER)
    return (int16_t)oscore_cbor_get_unsigned_integer(data);
  if (elem == CBOR_NEGATIVE_INTEGER)
    return (int16_t)oscore_cbor_get_negative_integer(data);
  if ((elem == CBOR_BYTE_STRING) | (elem == CBOR_TEXT_STRING)){
    size_t len = oscore_cbor_get_element_size(data);
    uint8_t *ident = NULL;
    ident = realloc(ident, len);
    oscore_cbor_get_array(data, ident,(uint64_t)len);

/* verify that string a valid string and find tag value */
    for (int k=0; k < NR_OF_TAGS; k++){
      if (
        (strncmp((char *)ident, cwt_tags[k].tag_name, len) == 0)
        && (len == strlen(cwt_tags[k].tag_name)))
      {
        free(ident);
        return cwt_tags[k].tag_value;
      }  /* if  */
    }  /* for NR_OF_TAGS  */
    free(ident);
    return UNDEFINED_TAG;
  }  /* if BYTE_STRING  */
  return UNDEFINED_TAG;
}



/* Return length */
size_t
cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer, size_t buf_len)
{
  size_t ret = 0;
  size_t rem_size = buf_len;

  ret += oscore_cbor_put_array(&buffer, &rem_size, 3);
  ret += oscore_cbor_put_bytes(&buffer, &rem_size, NULL, 0);
  /* ret += cose encode attributyes */
  ret += oscore_cbor_put_bytes(&buffer, &rem_size,
                               ptr->ciphertext.s, ptr->ciphertext.length);
  return ret;
}

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);

/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *ptr)
{
  memset( ptr, 0, sizeof(cose_encrypt0_t));
}

void
cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
  ptr->alg = alg;
}

void
cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer,
                             size_t size)
{
  ptr->ciphertext.s = buffer;
  ptr->ciphertext.length = size;
}

void
cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size)
{
  ptr->plaintext.s = buffer;
  ptr->plaintext.length = size;
}
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr,
                             coap_bin_const_t *partial_iv)
{
  if (partial_iv == NULL || partial_iv->length == 0) {
    ptr->partial_iv.s = NULL;
    ptr->partial_iv.length = 0;
  }
  else {
    if (partial_iv->length > (int)sizeof(ptr->partial_iv_data))
      partial_iv->length = sizeof(ptr->partial_iv_data);
    memcpy(ptr->partial_iv_data, partial_iv->s, partial_iv->length);
    ptr->partial_iv.s = ptr->partial_iv_data;
    ptr->partial_iv.length = partial_iv->length;
  }
}

/* Return length */
coap_bin_const_t
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr)
{
  return ptr->partial_iv;
}

void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, coap_bin_const_t *key_id)
{
  if (key_id) {
    ptr->key_id = *key_id;
  }
  else {
    ptr->key_id.length = 0;
    ptr->key_id.s = NULL;
  }
}
/* Return length */
size_t
cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
  *buffer = ptr->key_id.s;
  return ptr->key_id.length;
}

size_t cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr,
                                     const uint8_t **buffer)
{
  *buffer = ptr->kid_context.s;
  return ptr->kid_context.length;
}

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr,
                                   coap_bin_const_t *kid_context)
{
  if (kid_context) {
    ptr->kid_context = *kid_context;
  }
  else {
    ptr->kid_context.length = 0;
    ptr->kid_context.s = NULL;
  }
}

void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, coap_bin_const_t *aad)
{
  if (aad) {
    ptr->aad = *aad;
  }
  else {
    ptr->aad.length = 0;
    ptr->aad.s = NULL;
  }
}

/* Returns 1 if successfull, 0 if key is of incorrect length. */
int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, coap_bin_const_t *key)
{
  if (key == NULL || key->length != 16) {
    return 0;
  }

  ptr->key = *key;
  return 1;
}

void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, coap_bin_const_t *nonce)
{
  if (nonce) {
    ptr->nonce = *nonce;
  }
  else {
    ptr->nonce.length = 0;
    ptr->nonce.s = NULL;
  }
}

int
cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer,
                      size_t ciphertext_len)
{
  coap_crypto_param_t params;
  size_t tag_len = cose_tag_len(ptr->alg);
  size_t max_result_len = ptr->plaintext.length + tag_len;

  if (ptr->key.s == NULL || ptr->key.length != (size_t)cose_key_len(ptr->alg)) {
    return -1;
  }
  if (ptr->nonce.s == NULL ||
      ptr->nonce.length != (size_t)cose_nonce_len(ptr->alg)) {
    return -2;
  }
  if( ptr->aad.s == NULL || ptr->aad.length == 0) {
    return -3;
  }
  if (ptr->plaintext.s == NULL ||
      (ptr->plaintext.length + tag_len) > ciphertext_len) {
    return -4;
  }

  memset(&params, 0, sizeof(params));
  params.alg = ptr->alg;
  params.params.aes.key = ptr->key;
  params.params.aes.nonce = ptr->nonce.s;
  params.params.aes.tag_len = tag_len;
  params.params.aes.l = 15 - ptr->nonce.length;
  if (!coap_crypto_aead_encrypt(&params, &ptr->plaintext, &ptr->aad,
                                ciphertext_buffer, &max_result_len)) {
    return -5;
  }
  return (int)max_result_len;
}

int
cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer,
                      size_t plaintext_len)
{
  int ret_len = 0;
  coap_crypto_param_t params;
  size_t tag_len = cose_tag_len(ptr->alg);
  size_t max_result_len =  ptr->ciphertext.length - tag_len;

  if(ptr->key.s == NULL || ptr->key.length != (size_t)cose_key_len(ptr->alg)) {
    return -1;
  }
  if (ptr->nonce.s == NULL ||
      ptr->nonce.length != (size_t)cose_nonce_len(ptr->alg)) {
    return -2;
  }
  if (ptr->aad.s == NULL || ptr->aad.length == 0) {
    return -3;
  }
  if (ptr->ciphertext.s == NULL ||
      ptr->ciphertext.length > (plaintext_len + tag_len)) {
    return -4;
  }

  memset(&params, 0, sizeof(params));
  params.alg = ptr->alg;
  params.params.aes.key = ptr->key;
  params.params.aes.nonce = ptr->nonce.s;
  params.params.aes.tag_len = tag_len;
  params.params.aes.l = 15 - ptr->nonce.length;
  if (!coap_crypto_aead_decrypt(&params, &ptr->ciphertext, &ptr->aad,
                                plaintext_buffer, &max_result_len)) {
    return -5;
  }
  ret_len =(int) max_result_len;
  return ret_len;
}

#ifdef HAVE_OSCORE_GROUP
/* ed25519 signature functions    */

void cose_sign1_init(cose_sign1_t *ptr){
  memset( ptr, 0, sizeof(cose_sign1_t));
}

void cose_sign1_set_alg(cose_sign1_t *ptr, int alg,
          int alg_param, int alg_kty){
  ptr->alg = alg;
  ptr->alg_param = alg_param;
  ptr->alg_kty = alg_kty;
}

void cose_sign1_set_ciphertext(cose_sign1_t *ptr, uint8_t *buffer,
                               size_t size){
  ptr->ciphertext.s = buffer;
  ptr->ciphertext.length = size;
}

/* Return length */
int cose_sign1_get_signature(cose_sign1_t *ptr, const uint8_t **buffer){
  *buffer = ptr->signature.s;
  return ptr->signature.length;
}

void cose_sign1_set_signature(cose_sign1_t *ptr, uint8_t *buffer){
  ptr->signature.s = buffer;
  ptr->signature.length = Ed25519_SIGNATURE_LEN;
}

void cose_sign1_set_sigstructure(cose_sign1_t *ptr, uint8_t *buffer,
                                 size_t size){
  ptr->sigstructure.s = buffer;
  ptr->sigstructure.length = size;
}

void cose_sign1_set_public_key(cose_sign1_t *ptr, coap_bin_const_t *buffer) {
  ptr->public_key = *buffer;
}

void cose_sign1_set_private_key(cose_sign1_t *ptr, coap_bin_const_t *buffer) {
  ptr->private_key = *buffer;
}

int cose_sign1_sign(cose_sign1_t *ptr){
   return oscore_edDSA_sign(ptr->alg, ptr->alg_param, &ptr->signature,
                            &ptr->ciphertext, &ptr->private_key,
                            &ptr->public_key);
}

int
cose_sign1_verify(cose_sign1_t *ptr)
{
   return oscore_edDSA_verify(ptr->alg, ptr->alg_param, &ptr->signature,
                              &ptr->ciphertext, &ptr->public_key);
}
#endif /* HAVE_OSCORE_GROUP */



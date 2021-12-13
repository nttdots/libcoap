/*
 * coap_crypto_internal.h -- Structures, Enums & Functions that are not
 * exposed to application programming
 *
 * Copyright (C) 2017-2022 Olaf Bergmann <bergmann@tzi.org>
 * Copyright (C) 2021-2022 Jon Shallow <supjps-ietf@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_crypto_internal.h
 * @brief COAP crypto internal information
 */

#ifndef COAP_CRYPTO_INTERNAL_H_
#define COAP_CRYPTO_INTERNAL_H_

/**
 * @ingroup internal_api
 * @defgroup crypto_internal OSCORE Crypto Support
 * Internal API for interfacing with Crypto libraries
 * @{
 */

#include "oscore/oscore_cose.h"

#ifndef COAP_CRYPTO_MAX_KEY_SIZE
#define COAP_CRYPTO_MAX_KEY_SIZE (32)
#endif /* COAP_CRYPTO_MAX_KEY_SIZE */

#ifndef COAP_OSCORE_DEFAULT_REPLAY_WINDOW
#define COAP_OSCORE_DEFAULT_REPLAY_WINDOW 32
#endif /* COAP_OSCORE_DEFAULT_REPLAY_WINDOW */

/**
 * The structure that holds the Crypto Key.
 */
typedef coap_bin_const_t coap_crypto_key_t;

/**
 * The structure that holds the AES Crypto information
 */
typedef struct coap_crypto_aes_ccm_t {
  coap_crypto_key_t key; /**< The Key to use */
  const uint8_t *nonce;  /**< must be exactly 15 - l bytes */
  size_t tag_len;        /**< The size of the Tag */
  size_t l;              /**< The number of bytes in the length field */
} coap_crypto_aes_ccm_t;

/**
 * The common structure that holds the Crypto information
 */
typedef struct coap_crypto_param_t {
  cose_alg_t alg; /**< The COSE algorith to use */
  union {
    coap_crypto_aes_ccm_t aes; /**< Used if AES type encryption */
    coap_crypto_key_t key;     /**< The key to use */
  } params;
} coap_crypto_param_t;

/**
 * Holds private key definitions
 */
struct coap_crypto_pri_key_t {
  void *key_tls;               /**< Private Key in the used TLS format */
  coap_bin_const_t *key_value; /**< DER Value of the key abstracted
                                    from key_tls */
};                             /* typedef in coap_forward_decls.h */

/**
 * Holds public key definitions
 */
struct coap_crypto_pub_key_t {
  void *key_tls;               /**< Public Key in the used TLS format */
  coap_bin_const_t *key_value; /**< DER Value of the key abstracted
                                    from key_tls */
  size_t sign_size;            /**< Size of signature */
};                             /* typedef in coap_forward_decls.h */

/**
 * Check whether the defined cipher algorithm is supported by the underlying
 * crypto library.
 *
 * @param alg The COSE algorithm to check.
 *
 * @return @c 1 if there is support, else @c 0.
 */
int coap_crypto_check_cipher_alg(cose_alg_t alg);

/**
 * Check whether the defined hkdf algorithm is supported by the underlying
 * crypto library.
 *
 * @param alg The COSE algorithm to check.
 *
 * @return @c 1 if there is support, else @c 0.
 */
int coap_crypto_check_hkdf_alg(cose_alg_t alg);

/**
 * Encrypt the provided plaintext data
 *
 * @param params The Encrypt/Decrypt/Hash paramaters.
 * @param data The data to encrypt.
 * @param aad The additional AAD information.
 * @param result Where to put the encrypted data.
 * @param max_result_len The maximum size for @p result
 *                       (updated with actual size).
 *
 * @return @c 1 if the data was successfully encrypted, else @c 0.
 */
int coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                             coap_bin_const_t *data,
                             coap_bin_const_t *aad,
                             uint8_t *result,
                             size_t *max_result_len);

/**
 * Decrypt the provided encrypted data into plaintext.
 *
 * @param params The Encrypt/Decrypt/Hash paramaters.
 * @param data The data to decrypt.
 * @param aad The additional AAD information.
 * @param result Where to put the decrypted data.
 * @param max_result_len The maximum size for @p result
 *                       (updated with actual size).
 *
 * @return @c 1 if the data was successfully decrypted, else @c 0.
 */
int coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                             coap_bin_const_t *data,
                             coap_bin_const_t *aad,
                             uint8_t *result,
                             size_t *max_result_len);

/**
 * Create a HMAC hash of the provided data.
 *
 * @param alg The COSE algorithm to use.
 * @param key The key to use for the hash.
 * @param data The data to hash.
 * @param hmac Where to put the created hmac result if successful.
 *
 * @return @c 1 if the hmac of the data was successful, else @c 0.
 *         It is the responsibility of the caller to release the
 *         created hmac.
 */
int coap_crypto_hmac(cose_alg_t alg,
                     coap_bin_const_t *key,
                     coap_bin_const_t *data,
                     coap_bin_const_t **hmac);

#if defined(HAVE_OSCORE_GROUP) || defined(HAVE_OSCORE_EDHOC)

/**
 * Check whether the defined curve algorithm is supported by the underlying
 * crypto library.
 *
 * @param alg The COSE curve to check.
 *
 * @return @c 1 if there is support, else @c 0.
 */
int coap_crypto_check_curve_alg(cose_curve_t alg);

/**
 * Check whether the defined hash algorithm is supported by the underlying
 * crypto library.
 *
 * @param alg The COSE hash to check.
 *
 * @return @c 1 if there is support, else @c 0.
 */
int coap_crypto_check_hash_alg(cose_alg_t alg);

/**
 * Load in the private key from the specific PEM file
 *
 * @param filename The file containing the private key in PEM.
 * @param private Where to hold the private information.
 *
 * @return @c 1 if the private key was successfully imported, else @c 0.
 */
int coap_crypto_read_pem_private_key(const char *filename,
                                     coap_crypto_pri_key_t **private);

/**
 * Load in the private key from the ASN1 hex definition
 *
 * @param binary The binary equivalent of the hex definition.
 * @param private Where to hold the private information.
 *
 * @return @c 1 if the private key was successfully imported, else @c 0.
 */
int coap_crypto_read_asn1_private_key(coap_bin_const_t *binary,
                                      coap_crypto_pri_key_t **private);

/**
 * Load in the private key from the raw hex definition
 *
 * @param curve The elliptic curve to use for the key.
 * @param binary The binary equivalent of the hex definition.
 * @param private Where to hold the private information.
 *
 * @return @c 1 if the private key was successfully imported, else @c 0.
 */
int coap_crypto_read_raw_private_key(cose_curve_t curve,
                                     coap_bin_const_t *binary,
                                     coap_crypto_pri_key_t **private);

/**
 * Duplicate the private key
 *
 * @param key The location of the public key.
 *
 * @return Duplicated private key or @c NULL if error.
 */
coap_crypto_pri_key_t *
coap_crypto_duplicate_private_key(coap_crypto_pri_key_t *key);

/**
 * Delete the private key previously generated
 *
 * @param key The location of the held private key.
 */
void coap_crypto_delete_private_key(coap_crypto_pri_key_t *key);

/**
 * Load in the public key from the specific PEM file
 *
 * @param filename The file containing the public key in PEM.
 * @param pubic Where to hold the public information.
 *
 * @return @c 1 if the public key was successfully imported, else @c 0.
 */
int coap_crypto_read_pem_public_key(const char *filename,
                                    coap_crypto_pub_key_t **public);

/**
 * Load in the public key from the ASN1 hex definition
 *
 * @param binary The binary equivalent of the hex definition.
 * @param pubic Where to hold the public information.
 *
 * @return @c 1 if the public key was successfully imported, else @c 0.
 */
int coap_crypto_read_asn1_public_key(coap_bin_const_t *binary,
                                     coap_crypto_pub_key_t **public);

/**
 * Load in the public key from the raw hex definition
 *
 * @param curve The elliptic curve to use for the key.
 * @param binary The binary equivalent of the hex definition.
 * @param pubic Where to hold the public information.
 *
 * @return @c 1 if the public key was successfully imported, else @c 0.
 */
int coap_crypto_read_raw_public_key(cose_curve_t curve,
                                    coap_bin_const_t *binary,
                                    coap_crypto_pub_key_t **public);

/**
 * Duplicate the public key
 *
 * @param key The location of the public key.
 *
 * @return Duplicated public key or @c NULL if error.
 */
coap_crypto_pub_key_t *
coap_crypto_duplicate_public_key(coap_crypto_pub_key_t *key);

/**
 * Delete the public key previously generated
 *
 * @param key The location of the held public key.
 */
void coap_crypto_delete_public_key(coap_crypto_pub_key_t *key);

/**
 * Create the signature for the specified text
 *
 * @param hash The hash to use.
 * @param signature The signature to fill in
 * @param text The text to sign
 * @param private_key The private key to use for the signature
 *
 * @return @c 1 if the data was successfully signed, else @c 0.
 */
int coap_crypto_hash_sign(cose_alg_t hash,
                          coap_binary_t *signature,
                          coap_bin_const_t *text,
                          coap_crypto_pri_key_t *private_key);

/**
 * Verify the signature for the specified text
 *
 * @param hash The hash to use.
 * @param signature The signature to verify
 * @param text The text to verify
 * @param public_key The public key to use for the signature
 *
 * @return @c 1 if the data was successfully verified, else @c 0.
 */
int coap_crypto_hash_verify(cose_alg_t hash,
                            coap_binary_t *signature,
                            coap_bin_const_t *text,
                            coap_crypto_pub_key_t *public_key);

/**
 * Generate a private an/or public key based on @p curve.
 *
 * @param curve The elliptic curve to use.
 * @param private  Where to put the created private key
 *                 (or NULL if not required).
 * @param public  Where to put the created public key
 *                (or NULL if not required).
 *
 * @return @c 1 if the key(s) were successfully generated, else @c 0.
 *         It is the responsibility of the caller to release any
 *         created keys.
 */
int coap_crypto_gen_pkey(cose_curve_t curve,
                         coap_bin_const_t **private,
                         coap_bin_const_t **public);

/**
 * Derive a shared secret from local private key and peer public key.
 *
 * @param curve The elliptic curve to use.
 * @param private The local private key.
 * @param peer_public The peer public key.
 * @param shared_secret Where to put the created shared secret.
 *
 * @return @c 1 if the shared secret was successfully generated, else @c 0.
 *         It is the responsibility of the caller to release the
 *         created shared_secret.
 */
int coap_crypto_derive_shared_secret(cose_curve_t curve,
                                     coap_bin_const_t *local_private,
                                     coap_bin_const_t *peer_public,
                                     coap_bin_const_t **shared_secret);

/**
 * Create a hash of the provided data.
 *
 * @param params The Encrypt/Decrypt/Hash paramaters.
 * @param data The data to hash.
 * @param hash Where to put the hash result if successful.
 *
 * @return @c 1 if the data was successfully hashed, else @c 0.
 *         It is the responsibility of the caller to release the
 *         created hash.
 */
int coap_crypto_hash(cose_alg_t alg,
                     const coap_bin_const_t *data,
                     coap_bin_const_t **hash);

#endif /* HAVE_OSCORE_GROUP || HAVE_OSCORE_EDHOC*/

/** @} */

#endif /* COAP_CRYPTO_INTERNAL_H_ */

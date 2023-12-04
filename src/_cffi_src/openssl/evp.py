# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/evp.h>\n\n'
TYPES = '\n\ntypedef ... EVP_CIPHER;\n\ntypedef ... EVP_CIPHER_CTX;\n\ntypedef ... EVP_MD;\n\ntypedef ... EVP_MD_CTX;\n\n\n\ntypedef ... EVP_PKEY;\n\ntypedef ... EVP_PKEY_CTX;\n\nstatic const int EVP_PKEY_RSA;\n\nstatic const int EVP_PKEY_DSA;\n\nstatic const int EVP_PKEY_DH;\n\nstatic const int EVP_PKEY_DHX;\n\nstatic const int EVP_PKEY_EC;\n\nstatic const int EVP_PKEY_X25519;\n\nstatic const int EVP_PKEY_ED25519;\n\nstatic const int EVP_PKEY_X448;\n\nstatic const int EVP_PKEY_ED448;\n\nstatic const int EVP_PKEY_POLY1305;\n\nstatic const int EVP_MAX_MD_SIZE;\n\nstatic const int EVP_CTRL_AEAD_SET_IVLEN;\n\nstatic const int EVP_CTRL_AEAD_GET_TAG;\n\nstatic const int EVP_CTRL_AEAD_SET_TAG;\n\n\n\nstatic const int Cryptography_HAS_SCRYPT;\n\nstatic const int Cryptography_HAS_EVP_PKEY_DHX;\n\nstatic const int Cryptography_HAS_EVP_PKEY_get_set_tls_encodedpoint;\n\nstatic const int Cryptography_HAS_ONESHOT_EVP_DIGEST_SIGN_VERIFY;\n\nstatic const long Cryptography_HAS_RAW_KEY;\n\nstatic const long Cryptography_HAS_EVP_DIGESTFINAL_XOF;\n\nstatic const long Cryptography_HAS_300_FIPS;\n\n'
FUNCTIONS = '\n\nconst EVP_CIPHER *EVP_get_cipherbyname(const char *);\n\nint EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);\n\nint EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,\n\n                      const unsigned char *, const unsigned char *, int);\n\nint EVP_CipherUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,\n\n                     const unsigned char *, int);\n\nint EVP_CipherFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);\n\nint EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *);\n\nint EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *);\n\nEVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);\n\nvoid EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *);\n\nint EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *, int);\n\nconst EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *);\n\n\n\nint EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *);\n\nint EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *);\n\nint EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t);\n\nint EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);\n\nint EVP_DigestFinalXOF(EVP_MD_CTX *, unsigned char *, size_t);\n\nconst EVP_MD *EVP_get_digestbyname(const char *);\n\n\n\nEVP_PKEY *EVP_PKEY_new(void);\n\nvoid EVP_PKEY_free(EVP_PKEY *);\n\nint EVP_PKEY_type(int);\n\nint EVP_PKEY_size(EVP_PKEY *);\n\nRSA *EVP_PKEY_get1_RSA(EVP_PKEY *);\n\nDSA *EVP_PKEY_get1_DSA(EVP_PKEY *);\n\nDH *EVP_PKEY_get1_DH(EVP_PKEY *);\n\n\n\nint EVP_PKEY_encrypt(EVP_PKEY_CTX *, unsigned char *, size_t *,\n\n                     const unsigned char *, size_t);\n\nint EVP_PKEY_decrypt(EVP_PKEY_CTX *, unsigned char *, size_t *,\n\n                     const unsigned char *, size_t);\n\n\n\nint EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);\n\nint EVP_SignUpdate(EVP_MD_CTX *, const void *, size_t);\n\nint EVP_SignFinal(EVP_MD_CTX *, unsigned char *, unsigned int *, EVP_PKEY *);\n\n\n\nint EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);\n\nint EVP_VerifyUpdate(EVP_MD_CTX *, const void *, size_t);\n\nint EVP_VerifyFinal(EVP_MD_CTX *, const unsigned char *, unsigned int,\n\n                    EVP_PKEY *);\n\n\n\nint EVP_DigestSignInit(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,\n\n                       ENGINE *, EVP_PKEY *);\n\nint EVP_DigestSignUpdate(EVP_MD_CTX *, const void *, size_t);\n\nint EVP_DigestSignFinal(EVP_MD_CTX *, unsigned char *, size_t *);\n\nint EVP_DigestVerifyInit(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,\n\n                         ENGINE *, EVP_PKEY *);\n\n\n\n\n\n\n\nEVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *, ENGINE *);\n\nEVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int, ENGINE *);\n\nEVP_PKEY_CTX *EVP_PKEY_CTX_dup(EVP_PKEY_CTX *);\n\nvoid EVP_PKEY_CTX_free(EVP_PKEY_CTX *);\n\nint EVP_PKEY_sign_init(EVP_PKEY_CTX *);\n\nint EVP_PKEY_sign(EVP_PKEY_CTX *, unsigned char *, size_t *,\n\n                  const unsigned char *, size_t);\n\nint EVP_PKEY_verify_init(EVP_PKEY_CTX *);\n\nint EVP_PKEY_verify(EVP_PKEY_CTX *, const unsigned char *, size_t,\n\n                    const unsigned char *, size_t);\n\nint EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *);\n\nint EVP_PKEY_verify_recover(EVP_PKEY_CTX *, unsigned char *,\n\n                            size_t *, const unsigned char *, size_t);\n\nint EVP_PKEY_encrypt_init(EVP_PKEY_CTX *);\n\nint EVP_PKEY_decrypt_init(EVP_PKEY_CTX *);\n\n\n\nint EVP_PKEY_set1_RSA(EVP_PKEY *, RSA *);\n\nint EVP_PKEY_set1_DSA(EVP_PKEY *, DSA *);\n\nint EVP_PKEY_set1_DH(EVP_PKEY *, DH *);\n\n\n\nint EVP_PKEY_cmp(const EVP_PKEY *, const EVP_PKEY *);\n\n\n\nint EVP_PKEY_keygen_init(EVP_PKEY_CTX *);\n\nint EVP_PKEY_keygen(EVP_PKEY_CTX *, EVP_PKEY **);\n\nint EVP_PKEY_derive_init(EVP_PKEY_CTX *);\n\nint EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *, EVP_PKEY *);\n\nint EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *, size_t *);\n\nint EVP_PKEY_set_type(EVP_PKEY *, int);\n\n\n\nint EVP_PKEY_id(const EVP_PKEY *);\n\nint Cryptography_EVP_PKEY_id(const EVP_PKEY *);\n\n\n\nEVP_MD_CTX *EVP_MD_CTX_new(void);\n\nvoid EVP_MD_CTX_free(EVP_MD_CTX *);\n\n/* Backwards compat aliases for pyOpenSSL */\n\nEVP_MD_CTX *Cryptography_EVP_MD_CTX_new(void);\n\nvoid Cryptography_EVP_MD_CTX_free(EVP_MD_CTX *);\n\n\n\n/* Added in 1.1.1 */\n\nint EVP_DigestSign(EVP_MD_CTX *, unsigned char *, size_t *,\n\n                   const unsigned char *, size_t);\n\nint EVP_DigestVerify(EVP_MD_CTX *, const unsigned char *, size_t,\n\n                     const unsigned char *, size_t);\n\n/* Added in 1.1.0 */\n\nsize_t EVP_PKEY_get1_tls_encodedpoint(EVP_PKEY *, unsigned char **);\n\nint EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY *, const unsigned char *,\n\n                                   size_t);\n\n\n\n/* EVP_PKEY * became const in 1.1.0 */\n\nint EVP_PKEY_bits(EVP_PKEY *);\n\n\n\nvoid OpenSSL_add_all_algorithms(void);\n\nint EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *);\n\n\n\nEC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *);\n\nint EVP_PKEY_set1_EC_KEY(EVP_PKEY *, EC_KEY *);\n\n\n\nint EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *, int, int, void *);\n\n\n\nint PKCS5_PBKDF2_HMAC(const char *, int, const unsigned char *, int, int,\n\n                      const EVP_MD *, int, unsigned char *);\n\n\n\nint EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *, const EVP_MD *);\n\n\n\nint EVP_PBE_scrypt(const char *, size_t, const unsigned char *, size_t,\n\n                   uint64_t, uint64_t, uint64_t, uint64_t, unsigned char *,\n\n                   size_t);\n\n\n\nEVP_PKEY *EVP_PKEY_new_raw_private_key(int, ENGINE *, const unsigned char *,\n\n                                       size_t);\n\nEVP_PKEY *EVP_PKEY_new_raw_public_key(int, ENGINE *, const unsigned char *,\n\n                                      size_t);\n\nint EVP_PKEY_get_raw_private_key(const EVP_PKEY *, unsigned char *, size_t *);\n\nint EVP_PKEY_get_raw_public_key(const EVP_PKEY *, unsigned char *, size_t *);\n\n\n\nint EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *);\n\nint EVP_default_properties_enable_fips(OSSL_LIB_CTX *, int);\n\n'
CUSTOMIZATIONS = "\n\n#ifdef EVP_PKEY_DHX\n\nconst long Cryptography_HAS_EVP_PKEY_DHX = 1;\n\n#else\n\nconst long Cryptography_HAS_EVP_PKEY_DHX = 0;\n\nconst long EVP_PKEY_DHX = -1;\n\n#endif\n\n\n\nint Cryptography_EVP_PKEY_id(const EVP_PKEY *key) {\n\n    return EVP_PKEY_id(key);\n\n}\n\nEVP_MD_CTX *Cryptography_EVP_MD_CTX_new(void) {\n\n    return EVP_MD_CTX_new();\n\n}\n\nvoid Cryptography_EVP_MD_CTX_free(EVP_MD_CTX *md) {\n\n    EVP_MD_CTX_free(md);\n\n}\n\n\n\n#if CRYPTOGRAPHY_IS_LIBRESSL || defined(OPENSSL_NO_SCRYPT)\n\nstatic const long Cryptography_HAS_SCRYPT = 0;\n\nint (*EVP_PBE_scrypt)(const char *, size_t, const unsigned char *, size_t,\n\n                      uint64_t, uint64_t, uint64_t, uint64_t, unsigned char *,\n\n                      size_t) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_SCRYPT = 1;\n\n#endif\n\n\n\n#if !CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_EVP_PKEY_get_set_tls_encodedpoint = 1;\n\n#else\n\nstatic const long Cryptography_HAS_EVP_PKEY_get_set_tls_encodedpoint = 0;\n\nsize_t (*EVP_PKEY_get1_tls_encodedpoint)(EVP_PKEY *, unsigned char **) = NULL;\n\nint (*EVP_PKEY_set1_tls_encodedpoint)(EVP_PKEY *, const unsigned char *,\n\n                                      size_t) = NULL;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_111\n\nstatic const long Cryptography_HAS_ONESHOT_EVP_DIGEST_SIGN_VERIFY = 0;\n\nstatic const long Cryptography_HAS_RAW_KEY = 0;\n\nstatic const long Cryptography_HAS_EVP_DIGESTFINAL_XOF = 0;\n\nint (*EVP_DigestFinalXOF)(EVP_MD_CTX *, unsigned char *, size_t) = NULL;\n\nint (*EVP_DigestSign)(EVP_MD_CTX *, unsigned char *, size_t *,\n\n                      const unsigned char *tbs, size_t) = NULL;\n\nint (*EVP_DigestVerify)(EVP_MD_CTX *, const unsigned char *, size_t,\n\n                        const unsigned char *, size_t) = NULL;\n\nEVP_PKEY *(*EVP_PKEY_new_raw_private_key)(int, ENGINE *, const unsigned char *,\n\n                                       size_t) = NULL;\n\nEVP_PKEY *(*EVP_PKEY_new_raw_public_key)(int, ENGINE *, const unsigned char *,\n\n                                      size_t) = NULL;\n\nint (*EVP_PKEY_get_raw_private_key)(const EVP_PKEY *, unsigned char *,\n\n                                    size_t *) = NULL;\n\nint (*EVP_PKEY_get_raw_public_key)(const EVP_PKEY *, unsigned char *,\n\n                                   size_t *) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_ONESHOT_EVP_DIGEST_SIGN_VERIFY = 1;\n\nstatic const long Cryptography_HAS_RAW_KEY = 1;\n\nstatic const long Cryptography_HAS_EVP_DIGESTFINAL_XOF = 1;\n\n#endif\n\n\n\n/* OpenSSL 1.1.0+ does this define for us, but if not present we'll do it */\n\n#if !defined(EVP_CTRL_AEAD_SET_IVLEN)\n\n# define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN\n\n#endif\n\n#if !defined(EVP_CTRL_AEAD_GET_TAG)\n\n# define EVP_CTRL_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG\n\n#endif\n\n#if !defined(EVP_CTRL_AEAD_SET_TAG)\n\n# define EVP_CTRL_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG\n\n#endif\n\n\n\n/* This is tied to X25519 support so we reuse the Cryptography_HAS_X25519\n\n   conditional to remove it. OpenSSL 1.1.0 didn't have this define, but\n\n   1.1.1 will when it is released. We can remove this in the distant\n\n   future when we drop 1.1.0 support. */\n\n#ifndef EVP_PKEY_X25519\n\n#define EVP_PKEY_X25519 NID_X25519\n\n#endif\n\n\n\n/* This is tied to X448 support so we reuse the Cryptography_HAS_X448\n\n   conditional to remove it. OpenSSL 1.1.1 adds this define.  We can remove\n\n   this in the distant future when we drop 1.1.0 support. */\n\n#ifndef EVP_PKEY_X448\n\n#define EVP_PKEY_X448 NID_X448\n\n#endif\n\n\n\n/* This is tied to ED25519 support so we reuse the Cryptography_HAS_ED25519\n\n   conditional to remove it. */\n\n#ifndef EVP_PKEY_ED25519\n\n#define EVP_PKEY_ED25519 NID_ED25519\n\n#endif\n\n\n\n/* This is tied to ED448 support so we reuse the Cryptography_HAS_ED448\n\n   conditional to remove it. */\n\n#ifndef EVP_PKEY_ED448\n\n#define EVP_PKEY_ED448 NID_ED448\n\n#endif\n\n\n\n/* This is tied to poly1305 support so we reuse the Cryptography_HAS_POLY1305\n\n   conditional to remove it. */\n\n#ifndef EVP_PKEY_POLY1305\n\n#define EVP_PKEY_POLY1305 NID_poly1305\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER\n\nstatic const long Cryptography_HAS_300_FIPS = 1;\n\n#else\n\nstatic const long Cryptography_HAS_300_FIPS = 0;\n\nint (*EVP_default_properties_is_fips_enabled)(OSSL_LIB_CTX *) = NULL;\n\nint (*EVP_default_properties_enable_fips)(OSSL_LIB_CTX *, int) = NULL;\n\n#endif\n\n"
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/ssl.h>\n\n\n\n/*\n\n * This is part of a work-around for the difficulty cffi has in dealing with\n\n * `STACK_OF(foo)` as the name of a type.  We invent a new, simpler name that\n\n * will be an alias for this type and use the alias throughout.  This works\n\n * together with another opaque typedef for the same name in the TYPES section.\n\n * Note that the result is an opaque type.\n\n */\n\ntypedef STACK_OF(X509) Cryptography_STACK_OF_X509;\n\ntypedef STACK_OF(X509_CRL) Cryptography_STACK_OF_X509_CRL;\n\ntypedef STACK_OF(X509_REVOKED) Cryptography_STACK_OF_X509_REVOKED;\n\n'
TYPES = '\n\ntypedef ... Cryptography_STACK_OF_X509;\n\ntypedef ... Cryptography_STACK_OF_X509_CRL;\n\ntypedef ... Cryptography_STACK_OF_X509_REVOKED;\n\n\n\ntypedef struct {\n\n    ASN1_OBJECT *algorithm;\n\n    ...;\n\n} X509_ALGOR;\n\n\n\ntypedef ... X509_ATTRIBUTE;\n\ntypedef ... X509_EXTENSION;\n\ntypedef ... X509_EXTENSIONS;\n\ntypedef ... X509_REQ;\n\ntypedef ... X509_REVOKED;\n\ntypedef ... X509_CRL;\n\ntypedef ... X509;\n\n\n\ntypedef ... NETSCAPE_SPKI;\n\n\n\ntypedef ... PKCS8_PRIV_KEY_INFO;\n\n\n\ntypedef void (*sk_X509_EXTENSION_freefunc)(X509_EXTENSION *);\n\n'
FUNCTIONS = "\n\nX509 *X509_new(void);\n\nvoid X509_free(X509 *);\n\nX509 *X509_dup(X509 *);\n\nint X509_cmp(const X509 *, const X509 *);\n\nint X509_up_ref(X509 *);\n\n\n\nint X509_print_ex(BIO *, X509 *, unsigned long, unsigned long);\n\n\n\nint X509_set_version(X509 *, long);\n\n\n\nEVP_PKEY *X509_get_pubkey(X509 *);\n\nint X509_set_pubkey(X509 *, EVP_PKEY *);\n\n\n\nunsigned char *X509_alias_get0(X509 *, int *);\n\nint X509_sign(X509 *, EVP_PKEY *, const EVP_MD *);\n\n\n\nint X509_digest(const X509 *, const EVP_MD *, unsigned char *, unsigned int *);\n\n\n\nASN1_TIME *X509_gmtime_adj(ASN1_TIME *, long);\n\n\n\nunsigned long X509_subject_name_hash(X509 *);\n\n\n\nint X509_set_subject_name(X509 *, X509_NAME *);\n\n\n\nint X509_set_issuer_name(X509 *, X509_NAME *);\n\n\n\nint X509_add_ext(X509 *, X509_EXTENSION *, int);\n\nX509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *);\n\n\n\nASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *);\n\nvoid X509_EXTENSION_free(X509_EXTENSION *);\n\n\n\nint X509_REQ_set_version(X509_REQ *, long);\n\nX509_REQ *X509_REQ_new(void);\n\nvoid X509_REQ_free(X509_REQ *);\n\nint X509_REQ_set_pubkey(X509_REQ *, EVP_PKEY *);\n\nint X509_REQ_set_subject_name(X509_REQ *, X509_NAME *);\n\nint X509_REQ_sign(X509_REQ *, EVP_PKEY *, const EVP_MD *);\n\nint X509_REQ_verify(X509_REQ *, EVP_PKEY *);\n\nEVP_PKEY *X509_REQ_get_pubkey(X509_REQ *);\n\nint X509_REQ_print_ex(BIO *, X509_REQ *, unsigned long, unsigned long);\n\nint X509_REQ_add_extensions(X509_REQ *, X509_EXTENSIONS *);\n\nX509_EXTENSIONS *X509_REQ_get_extensions(X509_REQ *);\n\nint X509_REQ_add1_attr_by_OBJ(X509_REQ *, const ASN1_OBJECT *,\n\n                              int, const unsigned char *, int);\n\n\n\nint X509V3_EXT_print(BIO *, X509_EXTENSION *, unsigned long, int);\n\nASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *);\n\n\n\nX509_REVOKED *X509_REVOKED_new(void);\n\nvoid X509_REVOKED_free(X509_REVOKED *);\n\n\n\nint X509_REVOKED_set_serialNumber(X509_REVOKED *, ASN1_INTEGER *);\n\n\n\nint X509_REVOKED_add_ext(X509_REVOKED *, X509_EXTENSION*, int);\n\nint X509_REVOKED_add1_ext_i2d(X509_REVOKED *, int, void *, int, unsigned long);\n\nX509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *, int);\n\n\n\nint X509_REVOKED_set_revocationDate(X509_REVOKED *, ASN1_TIME *);\n\n\n\nX509_CRL *X509_CRL_new(void);\n\nX509_CRL *X509_CRL_dup(X509_CRL *);\n\nX509_CRL *d2i_X509_CRL_bio(BIO *, X509_CRL **);\n\nint X509_CRL_add0_revoked(X509_CRL *, X509_REVOKED *);\n\nint X509_CRL_add_ext(X509_CRL *, X509_EXTENSION *, int);\n\nint X509_CRL_cmp(const X509_CRL *, const X509_CRL *);\n\nint X509_CRL_print(BIO *, X509_CRL *);\n\nint X509_CRL_set_issuer_name(X509_CRL *, X509_NAME *);\n\nint X509_CRL_set_version(X509_CRL *, long);\n\nint X509_CRL_sign(X509_CRL *, EVP_PKEY *, const EVP_MD *);\n\nint X509_CRL_sort(X509_CRL *);\n\nint X509_CRL_verify(X509_CRL *, EVP_PKEY *);\n\nint i2d_X509_CRL_bio(BIO *, X509_CRL *);\n\nvoid X509_CRL_free(X509_CRL *);\n\n\n\nint NETSCAPE_SPKI_verify(NETSCAPE_SPKI *, EVP_PKEY *);\n\nint NETSCAPE_SPKI_sign(NETSCAPE_SPKI *, EVP_PKEY *, const EVP_MD *);\n\nchar *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *);\n\nNETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *, int);\n\nEVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *);\n\nint NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *, EVP_PKEY *);\n\nNETSCAPE_SPKI *NETSCAPE_SPKI_new(void);\n\nvoid NETSCAPE_SPKI_free(NETSCAPE_SPKI *);\n\n\n\n/*  ASN1 serialization */\n\nint i2d_X509_bio(BIO *, X509 *);\n\nX509 *d2i_X509_bio(BIO *, X509 **);\n\n\n\nint i2d_X509_REQ_bio(BIO *, X509_REQ *);\n\nX509_REQ *d2i_X509_REQ_bio(BIO *, X509_REQ **);\n\n\n\nint i2d_PrivateKey_bio(BIO *, EVP_PKEY *);\n\nEVP_PKEY *d2i_PrivateKey_bio(BIO *, EVP_PKEY **);\n\nint i2d_PUBKEY_bio(BIO *, EVP_PKEY *);\n\nEVP_PKEY *d2i_PUBKEY_bio(BIO *, EVP_PKEY **);\n\n\n\nASN1_INTEGER *X509_get_serialNumber(X509 *);\n\nint X509_set_serialNumber(X509 *, ASN1_INTEGER *);\n\n\n\nconst char *X509_verify_cert_error_string(long);\n\n\n\nconst char *X509_get_default_cert_dir(void);\n\nconst char *X509_get_default_cert_file(void);\n\nconst char *X509_get_default_cert_dir_env(void);\n\nconst char *X509_get_default_cert_file_env(void);\n\n\n\nint i2d_RSAPrivateKey_bio(BIO *, RSA *);\n\nRSA *d2i_RSAPublicKey_bio(BIO *, RSA **);\n\nint i2d_RSAPublicKey_bio(BIO *, RSA *);\n\nint i2d_DSAPrivateKey_bio(BIO *, DSA *);\n\n\n\n/* These became const X509 in 1.1.0 */\n\nint X509_get_ext_count(X509 *);\n\nX509_EXTENSION *X509_get_ext(X509 *, int);\n\nX509_NAME *X509_get_subject_name(X509 *);\n\nX509_NAME *X509_get_issuer_name(X509 *);\n\n\n\n/* This became const ASN1_OBJECT * in 1.1.0 */\n\nX509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **,\n\n                                             ASN1_OBJECT *, int,\n\n                                             ASN1_OCTET_STRING *);\n\n\n\n\n\n/* This became const X509_EXTENSION * in 1.1.0 */\n\nint X509_EXTENSION_get_critical(X509_EXTENSION *);\n\n\n\n/* This became const X509_REVOKED * in 1.1.0 */\n\nint X509_REVOKED_get_ext_count(X509_REVOKED *);\n\nX509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *, int);\n\n\n\n/* This became const X509_CRL * in 1.1.0 */\n\nX509_EXTENSION *X509_CRL_get_ext(X509_CRL *, int);\n\nint X509_CRL_get_ext_count(X509_CRL *);\n\n\n\nint X509_CRL_get0_by_serial(X509_CRL *, X509_REVOKED **, ASN1_INTEGER *);\n\n\n\nX509_REVOKED *X509_REVOKED_dup(X509_REVOKED *);\n\nX509_REVOKED *Cryptography_X509_REVOKED_dup(X509_REVOKED *);\n\n\n\nint X509_get_signature_nid(const X509 *);\n\n\n\nconst X509_ALGOR *X509_get0_tbs_sigalg(const X509 *);\n\n\n\nlong X509_get_version(X509 *);\n\n\n\nASN1_TIME *X509_get_notBefore(X509 *);\n\nASN1_TIME *X509_get_notAfter(X509 *);\n\nASN1_TIME *X509_getm_notBefore(const X509 *);\n\nASN1_TIME *X509_getm_notAfter(const X509 *);\n\nconst ASN1_TIME *X509_get0_notBefore(const X509 *);\n\nconst ASN1_TIME *X509_get0_notAfter(const X509 *);\n\n\n\nlong X509_REQ_get_version(X509_REQ *);\n\nX509_NAME *X509_REQ_get_subject_name(X509_REQ *);\n\n\n\nCryptography_STACK_OF_X509 *sk_X509_new_null(void);\n\nvoid sk_X509_free(Cryptography_STACK_OF_X509 *);\n\nint sk_X509_num(Cryptography_STACK_OF_X509 *);\n\nint sk_X509_push(Cryptography_STACK_OF_X509 *, X509 *);\n\nX509 *sk_X509_value(Cryptography_STACK_OF_X509 *, int);\n\n\n\nX509_EXTENSIONS *sk_X509_EXTENSION_new_null(void);\n\nint sk_X509_EXTENSION_num(X509_EXTENSIONS *);\n\nX509_EXTENSION *sk_X509_EXTENSION_value(X509_EXTENSIONS *, int);\n\nint sk_X509_EXTENSION_push(X509_EXTENSIONS *, X509_EXTENSION *);\n\nint sk_X509_EXTENSION_insert(X509_EXTENSIONS *, X509_EXTENSION *, int);\n\nX509_EXTENSION *sk_X509_EXTENSION_delete(X509_EXTENSIONS *, int);\n\nvoid sk_X509_EXTENSION_free(X509_EXTENSIONS *);\n\nvoid sk_X509_EXTENSION_pop_free(X509_EXTENSIONS *, sk_X509_EXTENSION_freefunc);\n\n\n\nint sk_X509_REVOKED_num(Cryptography_STACK_OF_X509_REVOKED *);\n\nX509_REVOKED *sk_X509_REVOKED_value(Cryptography_STACK_OF_X509_REVOKED *, int);\n\n\n\nCryptography_STACK_OF_X509_CRL *sk_X509_CRL_new_null(void);\n\nvoid sk_X509_CRL_free(Cryptography_STACK_OF_X509_CRL *);\n\nint sk_X509_CRL_num(Cryptography_STACK_OF_X509_CRL *);\n\nint sk_X509_CRL_push(Cryptography_STACK_OF_X509_CRL *, X509_CRL *);\n\nX509_CRL *sk_X509_CRL_value(Cryptography_STACK_OF_X509_CRL *, int);\n\n\n\nlong X509_CRL_get_version(X509_CRL *);\n\nASN1_TIME *X509_CRL_get_lastUpdate(X509_CRL *);\n\nASN1_TIME *X509_CRL_get_nextUpdate(X509_CRL *);\n\nconst ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *);\n\nconst ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *);\n\nX509_NAME *X509_CRL_get_issuer(X509_CRL *);\n\nCryptography_STACK_OF_X509_REVOKED *X509_CRL_get_REVOKED(X509_CRL *);\n\n\n\n/* These aren't macros these arguments are all const X on openssl > 1.0.x */\n\nint X509_CRL_set_lastUpdate(X509_CRL *, ASN1_TIME *);\n\nint X509_CRL_set_nextUpdate(X509_CRL *, ASN1_TIME *);\n\nint X509_set_notBefore(X509 *, ASN1_TIME *);\n\nint X509_set_notAfter(X509 *, ASN1_TIME *);\n\n\n\nint X509_CRL_set1_lastUpdate(X509_CRL *, const ASN1_TIME *);\n\nint X509_CRL_set1_nextUpdate(X509_CRL *, const ASN1_TIME *);\n\nint X509_set1_notBefore(X509 *, const ASN1_TIME *);\n\nint X509_set1_notAfter(X509 *, const ASN1_TIME *);\n\n\n\nEC_KEY *d2i_EC_PUBKEY_bio(BIO *, EC_KEY **);\n\nint i2d_EC_PUBKEY_bio(BIO *, EC_KEY *);\n\nEC_KEY *d2i_ECPrivateKey_bio(BIO *, EC_KEY **);\n\nint i2d_ECPrivateKey_bio(BIO *, EC_KEY *);\n\n\n\n// declared in safestack\n\nint sk_ASN1_OBJECT_num(Cryptography_STACK_OF_ASN1_OBJECT *);\n\nASN1_OBJECT *sk_ASN1_OBJECT_value(Cryptography_STACK_OF_ASN1_OBJECT *, int);\n\nvoid sk_ASN1_OBJECT_free(Cryptography_STACK_OF_ASN1_OBJECT *);\n\nCryptography_STACK_OF_ASN1_OBJECT *sk_ASN1_OBJECT_new_null(void);\n\nint sk_ASN1_OBJECT_push(Cryptography_STACK_OF_ASN1_OBJECT *, ASN1_OBJECT *);\n\n\n\n/* these functions were added in 1.1.0 */\n\nconst ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *);\n\nconst ASN1_TIME *X509_REVOKED_get0_revocationDate(const X509_REVOKED *);\n\n"
CUSTOMIZATIONS = '\n\n/* Being kept around for pyOpenSSL */\n\nX509_REVOKED *Cryptography_X509_REVOKED_dup(X509_REVOKED *rev) {\n\n    return X509_REVOKED_dup(rev);\n\n}\n\n'
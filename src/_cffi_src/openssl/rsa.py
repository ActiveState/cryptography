# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <openssl/rsa.h>\n\n"
TYPES = "\n\ntypedef ... RSA;\n\ntypedef ... BN_GENCB;\n\nstatic const int RSA_PKCS1_PADDING;\n\nstatic const int RSA_NO_PADDING;\n\nstatic const int RSA_PKCS1_OAEP_PADDING;\n\nstatic const int RSA_PKCS1_PSS_PADDING;\n\nstatic const int RSA_F4;\n\n\n\nstatic const int Cryptography_HAS_RSA_OAEP_MD;\n\nstatic const int Cryptography_HAS_RSA_OAEP_LABEL;\n\n"
FUNCTIONS = "\n\nRSA *RSA_new(void);\n\nvoid RSA_free(RSA *);\n\nint RSA_generate_key_ex(RSA *, int, BIGNUM *, BN_GENCB *);\n\nint RSA_check_key(const RSA *);\n\nRSA *RSAPublicKey_dup(RSA *);\n\nint RSA_blinding_on(RSA *, BN_CTX *);\n\nint RSA_print(BIO *, const RSA *, int);\n\n\n\n/* added in 1.1.0 when the RSA struct was opaqued */\n\nint RSA_set0_key(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);\n\nint RSA_set0_factors(RSA *, BIGNUM *, BIGNUM *);\n\nint RSA_set0_crt_params(RSA *, BIGNUM *, BIGNUM *, BIGNUM *);\n\nvoid RSA_get0_key(const RSA *, const BIGNUM **, const BIGNUM **,\n\n                  const BIGNUM **);\n\nvoid RSA_get0_factors(const RSA *, const BIGNUM **, const BIGNUM **);\n\nvoid RSA_get0_crt_params(const RSA *, const BIGNUM **, const BIGNUM **,\n\n                         const BIGNUM **);\n\nint EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *, int);\n\nint EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *, int);\n\nint EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *, EVP_MD *);\n\nint EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *, unsigned char *, int);\n\n\n\nint EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *, EVP_MD *);\n\n"
CUSTOMIZATIONS = "\n\n#if !CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_RSA_OAEP_MD = 1;\n\nstatic const long Cryptography_HAS_RSA_OAEP_LABEL = 1;\n\n#else\n\nstatic const long Cryptography_HAS_RSA_OAEP_MD = 0;\n\nstatic const long Cryptography_HAS_RSA_OAEP_LABEL = 0;\n\nint (*EVP_PKEY_CTX_set_rsa_oaep_md)(EVP_PKEY_CTX *, EVP_MD *) = NULL;\n\nint (*EVP_PKEY_CTX_set0_rsa_oaep_label)(EVP_PKEY_CTX *, unsigned char *,\n\n                                        int) = NULL;\n\n#endif\n\n"

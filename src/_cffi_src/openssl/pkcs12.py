# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/pkcs12.h>\n\n'
TYPES = '\n\ntypedef ... PKCS12;\n\n'
FUNCTIONS = '\n\nvoid PKCS12_free(PKCS12 *);\n\n\n\nPKCS12 *d2i_PKCS12_bio(BIO *, PKCS12 **);\n\nint i2d_PKCS12_bio(BIO *, PKCS12 *);\n\nint PKCS12_parse(PKCS12 *, const char *, EVP_PKEY **, X509 **,\n\n                 Cryptography_STACK_OF_X509 **);\n\nPKCS12 *PKCS12_create(char *, char *, EVP_PKEY *, X509 *,\n\n                      Cryptography_STACK_OF_X509 *, int, int, int, int, int);\n\n'
CUSTOMIZATIONS = '\n\n'
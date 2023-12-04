# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <openssl/ecdsa.h>\n\n"
TYPES = "\n\ntypedef ... ECDSA_SIG;\n\n\n\ntypedef ... CRYPTO_EX_new;\n\ntypedef ... CRYPTO_EX_dup;\n\ntypedef ... CRYPTO_EX_free;\n\n"
FUNCTIONS = "\n\nint ECDSA_sign(int, const unsigned char *, int, unsigned char *,\n\n               unsigned int *, EC_KEY *);\n\nint ECDSA_verify(int, const unsigned char *, int, const unsigned char *, int,\n\n                 EC_KEY *);\n\nint ECDSA_size(const EC_KEY *);\n\n\n\n"
CUSTOMIZATIONS = "\n\n"

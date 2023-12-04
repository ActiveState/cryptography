# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/hmac.h>\n\n'
TYPES = '\n\ntypedef ... HMAC_CTX;\n\n'
FUNCTIONS = '\n\nint HMAC_Init_ex(HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *);\n\nint HMAC_Update(HMAC_CTX *, const unsigned char *, size_t);\n\nint HMAC_Final(HMAC_CTX *, unsigned char *, unsigned int *);\n\nint HMAC_CTX_copy(HMAC_CTX *, HMAC_CTX *);\n\n\n\nHMAC_CTX *HMAC_CTX_new(void);\n\nvoid HMAC_CTX_free(HMAC_CTX *ctx);\n\n'
CUSTOMIZATIONS = '\n\n'
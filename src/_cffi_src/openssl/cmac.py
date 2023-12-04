# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#if !defined(OPENSSL_NO_CMAC)\n\n#include <openssl/cmac.h>\n\n#endif\n\n'
TYPES = '\n\ntypedef ... CMAC_CTX;\n\n'
FUNCTIONS = '\n\nCMAC_CTX *CMAC_CTX_new(void);\n\nint CMAC_Init(CMAC_CTX *, const void *, size_t, const EVP_CIPHER *, ENGINE *);\n\nint CMAC_Update(CMAC_CTX *, const void *, size_t);\n\nint CMAC_Final(CMAC_CTX *, unsigned char *, size_t *);\n\nint CMAC_CTX_copy(CMAC_CTX *, const CMAC_CTX *);\n\nvoid CMAC_CTX_free(CMAC_CTX *);\n\n'
CUSTOMIZATIONS = '\n\n'
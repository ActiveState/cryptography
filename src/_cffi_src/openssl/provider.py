# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER\n\n#include <openssl/provider.h>\n\n#include <openssl/proverr.h>\n\n#endif\n\n"
TYPES = "\n\nstatic const long Cryptography_HAS_PROVIDERS;\n\n\n\ntypedef ... OSSL_PROVIDER;\n\ntypedef ... OSSL_LIB_CTX;\n\n\n\nstatic const long PROV_R_BAD_DECRYPT;\n\nstatic const long PROV_R_XTS_DUPLICATED_KEYS;\n\nstatic const long PROV_R_WRONG_FINAL_BLOCK_LENGTH;\n\n"
FUNCTIONS = "\n\nOSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *, const char *);\n\nint OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);\n\n"
CUSTOMIZATIONS = "\n\n#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER\n\nstatic const long Cryptography_HAS_PROVIDERS = 1;\n\n#else\n\nstatic const long Cryptography_HAS_PROVIDERS = 0;\n\ntypedef void OSSL_PROVIDER;\n\ntypedef void OSSL_LIB_CTX;\n\nstatic const long PROV_R_BAD_DECRYPT = 0;\n\nstatic const long PROV_R_XTS_DUPLICATED_KEYS = 0;\n\nstatic const long PROV_R_WRONG_FINAL_BLOCK_LENGTH = 0;\n\nOSSL_PROVIDER *(*OSSL_PROVIDER_load)(OSSL_LIB_CTX *, const char *) = NULL;\n\nint (*OSSL_PROVIDER_unload)(OSSL_PROVIDER *) = NULL;\n\n#endif\n\n"

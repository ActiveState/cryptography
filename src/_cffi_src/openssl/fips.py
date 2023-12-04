# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <openssl/crypto.h>\n\n"
TYPES = "\n\nstatic const long Cryptography_HAS_FIPS;\n\n"
FUNCTIONS = "\n\nint FIPS_mode_set(int);\n\nint FIPS_mode(void);\n\n"
CUSTOMIZATIONS = "\n\n#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_OPENSSL_300_OR_GREATER\n\nstatic const long Cryptography_HAS_FIPS = 0;\n\nint (*FIPS_mode_set)(int) = NULL;\n\nint (*FIPS_mode)(void) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_FIPS = 1;\n\n#endif\n\n"

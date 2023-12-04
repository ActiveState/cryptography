# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/aes.h>\n\n'
TYPES = '\n\ntypedef ... AES_KEY;\n\n'
FUNCTIONS = '\n\nint AES_wrap_key(AES_KEY *, const unsigned char *, unsigned char *,\n\n                 const unsigned char *, unsigned int);\n\nint AES_unwrap_key(AES_KEY *, const unsigned char *, unsigned char *,\n\n                   const unsigned char *, unsigned int);\n\n'
CUSTOMIZATIONS = '\n\n'
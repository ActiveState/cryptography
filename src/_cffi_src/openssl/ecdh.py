# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <openssl/ecdh.h>\n\n"
TYPES = "\n\n"
FUNCTIONS = "\n\nlong SSL_CTX_set_ecdh_auto(SSL_CTX *, int);\n\n"
CUSTOMIZATIONS = "\n\n"

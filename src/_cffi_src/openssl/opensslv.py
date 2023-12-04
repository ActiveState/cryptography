# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/opensslv.h>\n\n'
TYPES = '\n\n/* Note that these will be resolved when cryptography is compiled and are NOT\n\n   guaranteed to be the version that it actually loads. */\n\nstatic const int OPENSSL_VERSION_NUMBER;\n\nstatic const char *const OPENSSL_VERSION_TEXT;\n\n'
FUNCTIONS = '\n\n'
CUSTOMIZATIONS = '\n\n'
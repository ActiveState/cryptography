# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/conf.h>\n\n'
TYPES = '\n\n'
FUNCTIONS = '\n\nvoid OPENSSL_config(const char *);\n\n/* This is a macro in 1.1.0 */\n\nvoid OPENSSL_no_config(void);\n\n'
CUSTOMIZATIONS = '\n\n'
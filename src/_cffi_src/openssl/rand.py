# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <openssl/rand.h>\n\n"
TYPES = "\n\ntypedef ... RAND_METHOD;\n\n"
FUNCTIONS = "\n\nint RAND_set_rand_method(const RAND_METHOD *);\n\nvoid RAND_add(const void *, int, double);\n\nint RAND_status(void);\n\nint RAND_bytes(unsigned char *, int);\n\n"
CUSTOMIZATIONS = "\n\n"

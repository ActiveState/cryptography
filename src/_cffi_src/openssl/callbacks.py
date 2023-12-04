# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <string.h>\n\n"
TYPES = "\n\ntypedef struct {\n\n    char *password;\n\n    int length;\n\n    int called;\n\n    int error;\n\n    int maxsize;\n\n} CRYPTOGRAPHY_PASSWORD_DATA;\n\n"
FUNCTIONS = (
    "\n\nint Cryptography_pem_password_cb(char *, int, int, void *);\n\n"
)
CUSTOMIZATIONS = "\n\ntypedef struct {\n\n    char *password;\n\n    int length;\n\n    int called;\n\n    int error;\n\n    int maxsize;\n\n} CRYPTOGRAPHY_PASSWORD_DATA;\n\n\n\nint Cryptography_pem_password_cb(char *buf, int size,\n\n                                  int rwflag, void *userdata) {\n\n    /* The password cb is only invoked if OpenSSL decides the private\n\n       key is encrypted. So this path only occurs if it needs a password */\n\n    CRYPTOGRAPHY_PASSWORD_DATA *st = (CRYPTOGRAPHY_PASSWORD_DATA *)userdata;\n\n    st->called += 1;\n\n    st->maxsize = size;\n\n    if (st->length == 0) {\n\n        st->error = -1;\n\n        return 0;\n\n    } else if (st->length < size) {\n\n        memcpy(buf, st->password, st->length);\n\n        return st->length;\n\n    } else {\n\n        st->error = -2;\n\n        return 0;\n\n    }\n\n}\n\n"

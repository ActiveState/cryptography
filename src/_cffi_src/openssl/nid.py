# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = "\n\n#include <openssl/obj_mac.h>\n\n"
TYPES = "\n\nstatic const int Cryptography_HAS_ED448;\n\nstatic const int Cryptography_HAS_ED25519;\n\nstatic const int Cryptography_HAS_POLY1305;\n\n\n\nstatic const int NID_undef;\n\nstatic const int NID_pbe_WithSHA1And3_Key_TripleDES_CBC;\n\nstatic const int NID_X25519;\n\nstatic const int NID_X448;\n\nstatic const int NID_ED25519;\n\nstatic const int NID_ED448;\n\nstatic const int NID_poly1305;\n\n\n\nstatic const int NID_subject_alt_name;\n\nstatic const int NID_crl_reason;\n\n\n\nstatic const int NID_pkcs7_signed;\n\n"
FUNCTIONS = "\n\n"
CUSTOMIZATIONS = "\n\n#ifndef NID_ED25519\n\nstatic const long Cryptography_HAS_ED25519 = 0;\n\nstatic const int NID_ED25519 = 0;\n\n#else\n\nstatic const long Cryptography_HAS_ED25519 = 1;\n\n#endif\n\n#ifndef NID_ED448\n\nstatic const long Cryptography_HAS_ED448 = 0;\n\nstatic const int NID_ED448 = 0;\n\n#else\n\nstatic const long Cryptography_HAS_ED448 = 1;\n\n#endif\n\n#ifndef NID_poly1305\n\nstatic const long Cryptography_HAS_POLY1305 = 0;\n\nstatic const int NID_poly1305 = 0;\n\n#else\n\nstatic const long Cryptography_HAS_POLY1305 = 1;\n\n#endif\n\n"

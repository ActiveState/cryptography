# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/dsa.h>\n\n'
TYPES = '\n\ntypedef ... DSA;\n\n'
FUNCTIONS = '\n\nint DSA_generate_key(DSA *);\n\nDSA *DSA_new(void);\n\nvoid DSA_free(DSA *);\n\nDSA *DSAparams_dup(DSA *);\n\nint DSA_size(const DSA *);\n\nint DSA_sign(int, const unsigned char *, int, unsigned char *, unsigned int *,\n\n             DSA *);\n\nint DSA_verify(int, const unsigned char *, int, const unsigned char *, int,\n\n               DSA *);\n\n\n\n/* added in 1.1.0 to access the opaque struct */\n\nvoid DSA_get0_pqg(const DSA *, const BIGNUM **, const BIGNUM **,\n\n                  const BIGNUM **);\n\nint DSA_set0_pqg(DSA *, BIGNUM *, BIGNUM *, BIGNUM *);\n\nvoid DSA_get0_key(const DSA *, const BIGNUM **, const BIGNUM **);\n\nint DSA_set0_key(DSA *, BIGNUM *, BIGNUM *);\n\nint DSA_generate_parameters_ex(DSA *, int, unsigned char *, int,\n\n                               int *, unsigned long *, BN_GENCB *);\n\n'
CUSTOMIZATIONS = '\n\n'
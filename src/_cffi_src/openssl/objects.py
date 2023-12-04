# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/objects.h>\n\n'
TYPES = '\n\ntypedef struct {\n\n    int type;\n\n    int alias;\n\n    const char *name;\n\n    const char *data;\n\n} OBJ_NAME;\n\n\n\nstatic const long OBJ_NAME_TYPE_MD_METH;\n\n'
FUNCTIONS = '\n\nconst char *OBJ_nid2ln(int);\n\nconst char *OBJ_nid2sn(int);\n\nint OBJ_obj2nid(const ASN1_OBJECT *);\n\nint OBJ_sn2nid(const char *);\n\nint OBJ_txt2nid(const char *);\n\nASN1_OBJECT *OBJ_txt2obj(const char *, int);\n\n'
CUSTOMIZATIONS = '\n\n'
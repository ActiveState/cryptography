# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import os

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "src/osrandom_engine.h")) as f:
    INCLUDES = f.read()
TYPES = "\n\nstatic const char *const Cryptography_osrandom_engine_name;\n\nstatic const char *const Cryptography_osrandom_engine_id;\n\n"
FUNCTIONS = "\n\nint Cryptography_add_osrandom_engine(void);\n\n"
with open(os.path.join(HERE, "src/osrandom_engine.c")) as f:
    CUSTOMIZATIONS = f.read()

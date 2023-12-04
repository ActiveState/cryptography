# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.backends.interfaces import Backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)


def load_pem_private_key(data, password, backend=None):
    backend = _get_backend(backend)
    return backend.load_pem_private_key(data, password)


def load_pem_public_key(data, backend=None):
    backend = _get_backend(backend)
    return backend.load_pem_public_key(data)


def load_pem_parameters(data, backend=None):
    backend = _get_backend(backend)
    return backend.load_pem_parameters(data)


def load_der_private_key(data, password, backend=None):
    backend = _get_backend(backend)
    return backend.load_der_private_key(data, password)


def load_der_public_key(data, backend=None):
    backend = _get_backend(backend)
    return backend.load_der_public_key(data)


def load_der_parameters(data, backend=None):
    backend = _get_backend(backend)
    return backend.load_der_parameters(data)

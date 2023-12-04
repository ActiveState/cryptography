# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import abc
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import _serialization
_ED25519_KEY_SIZE = 32
_ED25519_SIG_SIZE = 64

class Ed25519PublicKey(metaclass=abc.ABCMeta):

    @classmethod
    def from_public_bytes(cls, data):
        from cryptography.hazmat.backends.openssl.backend import backend
        if not backend.ed25519_supported():
            raise UnsupportedAlgorithm('ed25519 is not supported by this version of OpenSSL.', _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)
        return backend.ed25519_load_public_bytes(data)

    @abc.abstractmethod
    def public_bytes(self, encoding, format):
        """

        The serialized bytes of the public key.

        """

    @abc.abstractmethod
    def verify(self, signature, data):
        """

        Verify the signature.

        """

class Ed25519PrivateKey(metaclass=abc.ABCMeta):

    @classmethod
    def generate(cls):
        from cryptography.hazmat.backends.openssl.backend import backend
        if not backend.ed25519_supported():
            raise UnsupportedAlgorithm('ed25519 is not supported by this version of OpenSSL.', _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)
        return backend.ed25519_generate_key()

    @classmethod
    def from_private_bytes(cls, data):
        from cryptography.hazmat.backends.openssl.backend import backend
        if not backend.ed25519_supported():
            raise UnsupportedAlgorithm('ed25519 is not supported by this version of OpenSSL.', _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)
        return backend.ed25519_load_private_bytes(data)

    @abc.abstractmethod
    def public_key(self):
        """

        The Ed25519PublicKey derived from the private key.

        """

    @abc.abstractmethod
    def private_bytes(self, encoding, format, encryption_algorithm):
        """

        The serialized bytes of the private key.

        """

    @abc.abstractmethod
    def sign(self, data):
        """

        Signs the data.

        """
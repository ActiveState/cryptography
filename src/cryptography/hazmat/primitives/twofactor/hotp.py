# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import base64
import struct
from urllib.parse import quote, urlencode

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.backends.interfaces import Backend, HMACBackend
from cryptography.hazmat.primitives import constant_time, hmac
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA512
from cryptography.hazmat.primitives.twofactor import InvalidToken

_ALLOWED_HASH_TYPES = typing.Union[SHA1, SHA256, SHA512]


def _generate_uri(hotp, type_name, account_name, issuer, extra_parameters):
    parameters = [
        ("digits", hotp._length),
        ("secret", base64.b32encode(hotp._key)),
        ("algorithm", hotp._algorithm.name.upper()),
    ]
    if issuer is not None:
        parameters.append(("issuer", issuer))
    parameters.extend(extra_parameters)
    uriparts = {
        "type": type_name,
        "label": "%s:%s" % (quote(issuer), quote(account_name))
        if issuer
        else quote(account_name),
        "parameters": urlencode(parameters),
    }
    return "otpauth://{type}/{label}?{parameters}".format(**uriparts)


class HOTP(object):
    def __init__(
        self, key, length, algorithm, backend=None, enforce_key_length=True
    ):
        backend = _get_backend(backend)
        if not isinstance(backend, HMACBackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement HMACBackend.",
                _Reasons.BACKEND_MISSING_INTERFACE,
            )
        if len(key) < 16 and enforce_key_length is True:
            raise ValueError("Key length has to be at least 128 bits.")
        if not isinstance(length, int):
            raise TypeError("Length parameter must be an integer type.")
        if length < 6 or length > 8:
            raise ValueError("Length of HOTP has to be between 6 to 8.")
        if not isinstance(algorithm, (SHA1, SHA256, SHA512)):
            raise TypeError("Algorithm must be SHA1, SHA256 or SHA512.")
        self._key = key
        self._length = length
        self._algorithm = algorithm
        self._backend = backend

    def generate(self, counter):
        truncated_value = self._dynamic_truncate(counter)
        hotp = truncated_value % 10**self._length
        return "{0:0{1}}".format(hotp, self._length).encode()

    def verify(self, hotp, counter):
        if not constant_time.bytes_eq(self.generate(counter), hotp):
            raise InvalidToken("Supplied HOTP value does not match.")

    def _dynamic_truncate(self, counter):
        ctx = hmac.HMAC(self._key, self._algorithm, self._backend)
        ctx.update(struct.pack(">Q", counter))
        hmac_value = ctx.finalize()
        offset = hmac_value[len(hmac_value) - 1] & 15
        p = hmac_value[offset : offset + 4]
        return struct.unpack(">I", p)[0] & 2147483647

    def get_provisioning_uri(self, account_name, counter, issuer):
        return _generate_uri(
            self, "hotp", account_name, issuer, [("counter", int(counter))]
        )

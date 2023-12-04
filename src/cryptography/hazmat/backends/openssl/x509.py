# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import datetime
import warnings

from cryptography import utils, x509

# This exists for pyOpenSSL compatibility and SHOULD NOT BE USED
# WE WILL REMOVE THIS VERY SOON.


def _Certificate(backend, x509):  # noqa: N802
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
    )
    return backend._ossl2cert(x509)


# This exists for pyOpenSSL compatibility and SHOULD NOT BE USED
# WE WILL REMOVE THIS VERY SOON.


def _CertificateSigningRequest(backend, x509_req):  # noqa: N802
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
    )
    return backend._ossl2csr(x509_req)


# This exists for pyOpenSSL compatibility and SHOULD NOT BE USED
# WE WILL REMOVE THIS VERY SOON.


def _CertificateRevocationList(backend, x509_crl):  # noqa: N802
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
    )
    return backend._ossl2crl(x509_crl)


class _RawRevokedCertificate(x509.RevokedCertificate):
    def __init__(self, serial_number, revocation_date, extensions):
        self._serial_number = serial_number
        self._revocation_date = revocation_date
        self._extensions = extensions

    @property
    def serial_number(self):
        return self._serial_number

    @property
    def revocation_date(self):
        return self._revocation_date

    @property
    def extensions(self):
        return self._extensions

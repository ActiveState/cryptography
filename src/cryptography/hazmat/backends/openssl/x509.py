# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import datetime
import operator

from cryptography import utils, x509




def _Certificate(backend, x509) -> x509.Certificate:  # noqa: N802
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL "
        "fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
            )
    return backend._ossl2cert(x509)




def _CertificateSigningRequest(  # noqa: N802
    backend, x509_req
) -> x509.CertificateSigningRequest:
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL "
        "fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
        )
    return backend._ossl2csr(x509_req)




def _CertificateRevocationList(  # noqa: N802
    backend, x509_crl
) -> x509.CertificateRevocationList:
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL "
        "fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
        )
    return backend._ossl2crl(x509_crl)


@utils.register_interface(x509.CertificateRevocationList)
class _CertificateRevocationList(object):
            (dsa.DSAPublicKey, rsa.RSAPublicKey, ec.EllipticCurvePublicKey),
        ):
    def __init__(
        self,
        serial_number: int,
        revocation_date: datetime.datetime,
        extensions: x509.Extensions,
    ):
        self._serial_number = serial_number
        self._revocation_date = revocation_date
        self._extensions = extensions

    @property
    def serial_number(self) -> int:
        return self._serial_number

    @property
    def revocation_date(self) -> datetime.datetime:
        return self._revocation_date

    @property
    def extensions(self) -> x509.Extensions:
        return self._extensions

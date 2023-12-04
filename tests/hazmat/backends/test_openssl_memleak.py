# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import json
import os
import subprocess
import sys
import textwrap
import pytest
from cryptography.hazmat.bindings.openssl.binding import Binding
MEMORY_LEAK_SCRIPT = '\n\nimport sys\n\n\n\n\n\ndef main(argv):\n\n    import gc\n\n    import json\n\n\n\n    import cffi\n\n\n\n    from cryptography.hazmat.bindings._openssl import ffi, lib\n\n\n\n    heap = {}\n\n\n\n    BACKTRACE_ENABLED = False\n\n    if BACKTRACE_ENABLED:\n\n        backtrace_ffi = cffi.FFI()\n\n        backtrace_ffi.cdef(\'\'\'\n\n            int backtrace(void **, int);\n\n            char **backtrace_symbols(void *const *, int);\n\n        \'\'\')\n\n        backtrace_lib = backtrace_ffi.dlopen(None)\n\n\n\n        def backtrace():\n\n            buf = backtrace_ffi.new("void*[]", 24)\n\n            length = backtrace_lib.backtrace(buf, len(buf))\n\n            return (buf, length)\n\n\n\n        def symbolize_backtrace(trace):\n\n            (buf, length) = trace\n\n            symbols = backtrace_lib.backtrace_symbols(buf, length)\n\n            stack = [\n\n                backtrace_ffi.string(symbols[i]).decode()\n\n                for i in range(length)\n\n            ]\n\n            lib.Cryptography_free_wrapper(symbols, backtrace_ffi.NULL, 0)\n\n            return stack\n\n    else:\n\n        def backtrace():\n\n            return None\n\n\n\n        def symbolize_backtrace(trace):\n\n            return None\n\n\n\n    @ffi.callback("void *(size_t, const char *, int)")\n\n    def malloc(size, path, line):\n\n        ptr = lib.Cryptography_malloc_wrapper(size, path, line)\n\n        heap[ptr] = (size, path, line, backtrace())\n\n        return ptr\n\n\n\n    @ffi.callback("void *(void *, size_t, const char *, int)")\n\n    def realloc(ptr, size, path, line):\n\n        if ptr != ffi.NULL:\n\n            del heap[ptr]\n\n        new_ptr = lib.Cryptography_realloc_wrapper(ptr, size, path, line)\n\n        heap[new_ptr] = (size, path, line, backtrace())\n\n        return new_ptr\n\n\n\n    @ffi.callback("void(void *, const char *, int)")\n\n    def free(ptr, path, line):\n\n        if ptr != ffi.NULL:\n\n            del heap[ptr]\n\n            lib.Cryptography_free_wrapper(ptr, path, line)\n\n\n\n    result = lib.Cryptography_CRYPTO_set_mem_functions(malloc, realloc, free)\n\n    assert result == 1\n\n\n\n    # Trigger a bunch of initialization stuff.\n\n    from cryptography.hazmat.backends.openssl.backend import backend\n\n\n\n    start_heap = set(heap)\n\n\n\n    func(*argv[1:])\n\n    gc.collect()\n\n    gc.collect()\n\n    gc.collect()\n\n\n\n    if lib.CRYPTOGRAPHY_OPENSSL_300_OR_GREATER:\n\n        lib.OSSL_PROVIDER_unload(backend._binding._legacy_provider)\n\n        lib.OSSL_PROVIDER_unload(backend._binding._default_provider)\n\n\n\n    if lib.Cryptography_HAS_OPENSSL_CLEANUP:\n\n        lib.OPENSSL_cleanup()\n\n\n\n    # Swap back to the original functions so that if OpenSSL tries to free\n\n    # something from its atexit handle it won\'t be going through a Python\n\n    # function, which will be deallocated when this function returns\n\n    result = lib.Cryptography_CRYPTO_set_mem_functions(\n\n        ffi.addressof(lib, "Cryptography_malloc_wrapper"),\n\n        ffi.addressof(lib, "Cryptography_realloc_wrapper"),\n\n        ffi.addressof(lib, "Cryptography_free_wrapper"),\n\n    )\n\n    assert result == 1\n\n\n\n    remaining = set(heap) - start_heap\n\n\n\n    if remaining:\n\n        sys.stdout.write(json.dumps(dict(\n\n            (int(ffi.cast("size_t", ptr)), {\n\n                "size": heap[ptr][0],\n\n                "path": ffi.string(heap[ptr][1]).decode(),\n\n                "line": heap[ptr][2],\n\n                "backtrace": symbolize_backtrace(heap[ptr][3]),\n\n            })\n\n            for ptr in remaining\n\n        )))\n\n        sys.stdout.flush()\n\n        sys.exit(255)\n\n\n\nmain(sys.argv)\n\n'

def assert_no_memory_leaks(s, argv=[]):
    env = os.environ.copy()
    env['PYTHONPATH'] = os.pathsep.join(sys.path)
    # When using pytest-cov it attempts to instrument subprocesses. This
    # causes the memleak tests to raise exceptions.
    # we don't need coverage so we remove the env vars.
    env.pop('COV_CORE_CONFIG', None)
    env.pop('COV_CORE_DATAFILE', None)
    env.pop('COV_CORE_SOURCE', None)
    argv = [sys.executable, '-c', '{}\n\n{}'.format(s, MEMORY_LEAK_SCRIPT)] + argv
    # Shell out to a fresh Python process because OpenSSL does not allow you to
    # install new memory hooks after the first malloc/free occurs.
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    assert proc.stderr is not None
    try:
        proc.wait()
        if proc.returncode == 255:
            # 255 means there was a leak, load the info about what mallocs
            # weren't freed.
            out = json.loads(proc.stdout.read().decode())
            raise AssertionError(out)
        elif proc.returncode != 0:
            # Any exception type will do to be honest
            raise ValueError(proc.stdout.read(), proc.stderr.read())
    finally:
        proc.stdout.close()
        proc.stderr.close()

def skip_if_memtesting_not_supported():
    return pytest.mark.skipif(not Binding().lib.Cryptography_HAS_MEM_FUNCTIONS, reason='Requires OpenSSL memory functions (>=1.1.0)')

@pytest.mark.skip_fips(reason='FIPS self-test sets allow_customize = 0')
@skip_if_memtesting_not_supported()
class TestAssertNoMemoryLeaks(object):

    def test_no_leak_no_malloc(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            pass\n\n        '))

    def test_no_leak_free(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            from cryptography.hazmat.bindings.openssl.binding import Binding\n\n            b = Binding()\n\n            name = b.lib.X509_NAME_new()\n\n            b.lib.X509_NAME_free(name)\n\n        '))

    def test_no_leak_gc(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            from cryptography.hazmat.bindings.openssl.binding import Binding\n\n            b = Binding()\n\n            name = b.lib.X509_NAME_new()\n\n            b.ffi.gc(name, b.lib.X509_NAME_free)\n\n        '))

    def test_leak(self):
        with pytest.raises(AssertionError):
            assert_no_memory_leaks(textwrap.dedent('\n\n            def func():\n\n                from cryptography.hazmat.bindings.openssl.binding import (\n\n                    Binding\n\n                )\n\n                b = Binding()\n\n                b.lib.X509_NAME_new()\n\n            '))

    def test_errors(self):
        with pytest.raises(ValueError):
            assert_no_memory_leaks(textwrap.dedent('\n\n            def func():\n\n                raise ZeroDivisionError\n\n            '))

@pytest.mark.skip_fips(reason='FIPS self-test sets allow_customize = 0')
@skip_if_memtesting_not_supported()
class TestOpenSSLMemoryLeaks(object):

    @pytest.mark.parametrize('path', ['x509/PKITS_data/certs/ValidcRLIssuerTest28EE.crt'])
    def test_der_x509_certificate_extensions(self, path):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func(path):\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n\n\n            import cryptography_vectors\n\n\n\n            with cryptography_vectors.open_vector_file(path, "rb") as f:\n\n                cert = x509.load_der_x509_certificate(\n\n                    f.read(), backend\n\n                )\n\n\n\n            cert.extensions\n\n        '), [path])

    @pytest.mark.parametrize('path', ['x509/cryptography.io.pem'])
    def test_pem_x509_certificate_extensions(self, path):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func(path):\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n\n\n            import cryptography_vectors\n\n\n\n            with cryptography_vectors.open_vector_file(path, "rb") as f:\n\n                cert = x509.load_pem_x509_certificate(\n\n                    f.read(), backend\n\n                )\n\n\n\n            cert.extensions\n\n        '), [path])

    def test_x509_csr_extensions(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives import hashes\n\n            from cryptography.hazmat.primitives.asymmetric import rsa\n\n\n\n            private_key = rsa.generate_private_key(\n\n                key_size=2048, public_exponent=65537, backend=backend\n\n            )\n\n            cert = x509.CertificateSigningRequestBuilder().subject_name(\n\n                x509.Name([])\n\n            ).add_extension(\n\n               x509.OCSPNoCheck(), critical=False\n\n            ).sign(private_key, hashes.SHA256(), backend)\n\n\n\n            cert.extensions\n\n        '))

    def test_ec_private_numbers_private_key(self):
        assert_no_memory_leaks(textwrap.dedent("\n\n        def func():\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives.asymmetric import ec\n\n\n\n            ec.EllipticCurvePrivateNumbers(\n\n                private_value=int(\n\n                    '280814107134858470598753916394807521398239633534281633982576099083'\n\n                    '35787109896602102090002196616273211495718603965098'\n\n                ),\n\n                public_numbers=ec.EllipticCurvePublicNumbers(\n\n                    curve=ec.SECP384R1(),\n\n                    x=int(\n\n                        '10036914308591746758780165503819213553101287571902957054148542'\n\n                        '504671046744460374996612408381962208627004841444205030'\n\n                    ),\n\n                    y=int(\n\n                        '17337335659928075994560513699823544906448896792102247714689323'\n\n                        '575406618073069185107088229463828921069465902299522926'\n\n                    )\n\n                )\n\n            ).private_key(backend)\n\n        "))

    def test_ec_derive_private_key(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives.asymmetric import ec\n\n            ec.derive_private_key(1, ec.SECP256R1(), backend)\n\n        '))

    def test_x25519_pubkey_from_private_key(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            from cryptography.hazmat.primitives.asymmetric import x25519\n\n            private_key = x25519.X25519PrivateKey.generate()\n\n            private_key.public_key()\n\n        '))

    def test_create_ocsp_request(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives import hashes\n\n            from cryptography.x509 import ocsp\n\n            import cryptography_vectors\n\n\n\n            path = "x509/PKITS_data/certs/ValidcRLIssuerTest28EE.crt"\n\n            with cryptography_vectors.open_vector_file(path, "rb") as f:\n\n                cert = x509.load_der_x509_certificate(\n\n                    f.read(), backend\n\n                )\n\n            builder = ocsp.OCSPRequestBuilder()\n\n            builder = builder.add_certificate(\n\n                cert, cert, hashes.SHA1()\n\n            ).add_extension(x509.OCSPNonce(b"0000"), False)\n\n            req = builder.build()\n\n        '))

    @pytest.mark.parametrize('path', ['pkcs12/cert-aes256cbc-no-key.p12', 'pkcs12/cert-key-aes256cbc.p12'])
    def test_load_pkcs12_key_and_certificates(self, path):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func(path):\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives.serialization import pkcs12\n\n            import cryptography_vectors\n\n\n\n            with cryptography_vectors.open_vector_file(path, "rb") as f:\n\n                pkcs12.load_key_and_certificates(\n\n                    f.read(), b"cryptography", backend\n\n                )\n\n        '), [path])

    def test_create_crl_with_idp(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            import datetime\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives import hashes\n\n            from cryptography.hazmat.primitives.asymmetric import ec\n\n            from cryptography.x509.oid import NameOID\n\n\n\n            key = ec.generate_private_key(ec.SECP256R1(), backend)\n\n            last_update = datetime.datetime(2002, 1, 1, 12, 1)\n\n            next_update = datetime.datetime(2030, 1, 1, 12, 1)\n\n            idp = x509.IssuingDistributionPoint(\n\n                full_name=None,\n\n                relative_name=x509.RelativeDistinguishedName([\n\n                    x509.NameAttribute(\n\n                        oid=x509.NameOID.ORGANIZATION_NAME, value=u"PyCA")\n\n                ]),\n\n                only_contains_user_certs=False,\n\n                only_contains_ca_certs=True,\n\n                only_some_reasons=None,\n\n                indirect_crl=False,\n\n                only_contains_attribute_certs=False,\n\n            )\n\n            builder = x509.CertificateRevocationListBuilder().issuer_name(\n\n                x509.Name([\n\n                    x509.NameAttribute(\n\n                        NameOID.COMMON_NAME, u"cryptography.io CA"\n\n                    )\n\n                ])\n\n            ).last_update(\n\n                last_update\n\n            ).next_update(\n\n                next_update\n\n            ).add_extension(\n\n                idp, True\n\n            )\n\n\n\n            crl = builder.sign(key, hashes.SHA256(), backend)\n\n            crl.extensions.get_extension_for_class(\n\n                x509.IssuingDistributionPoint\n\n            )\n\n        '))

    def test_create_certificate_with_extensions(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            import datetime\n\n\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives import hashes\n\n            from cryptography.hazmat.primitives.asymmetric import ec\n\n            from cryptography.x509.oid import (\n\n                AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID\n\n            )\n\n\n\n            private_key = ec.generate_private_key(ec.SECP256R1(), backend)\n\n\n\n            not_valid_before = datetime.datetime.now()\n\n            not_valid_after = not_valid_before + datetime.timedelta(days=365)\n\n\n\n            aia = x509.AuthorityInformationAccess([\n\n                x509.AccessDescription(\n\n                    AuthorityInformationAccessOID.OCSP,\n\n                    x509.UniformResourceIdentifier(u"http://ocsp.domain.com")\n\n                ),\n\n                x509.AccessDescription(\n\n                    AuthorityInformationAccessOID.CA_ISSUERS,\n\n                    x509.UniformResourceIdentifier(u"http://domain.com/ca.crt")\n\n                )\n\n            ])\n\n            sans = [u\'*.example.org\', u\'foobar.example.net\']\n\n            san = x509.SubjectAlternativeName(list(map(x509.DNSName, sans)))\n\n\n\n            ski = x509.SubjectKeyIdentifier.from_public_key(\n\n                private_key.public_key()\n\n            )\n\n            eku = x509.ExtendedKeyUsage([\n\n                ExtendedKeyUsageOID.CLIENT_AUTH,\n\n                ExtendedKeyUsageOID.SERVER_AUTH,\n\n                ExtendedKeyUsageOID.CODE_SIGNING,\n\n            ])\n\n\n\n            builder = x509.CertificateBuilder().serial_number(\n\n                777\n\n            ).issuer_name(x509.Name([\n\n                x509.NameAttribute(NameOID.COUNTRY_NAME, u\'US\'),\n\n            ])).subject_name(x509.Name([\n\n                x509.NameAttribute(NameOID.COUNTRY_NAME, u\'US\'),\n\n            ])).public_key(\n\n                private_key.public_key()\n\n            ).add_extension(\n\n                aia, critical=False\n\n            ).not_valid_before(\n\n                not_valid_before\n\n            ).not_valid_after(\n\n                not_valid_after\n\n            )\n\n\n\n            cert = builder.sign(private_key, hashes.SHA256(), backend)\n\n            cert.extensions\n\n        '))

    def test_write_pkcs12_key_and_certificates(self):
        assert_no_memory_leaks(textwrap.dedent('\n\n        def func():\n\n            import os\n\n            from cryptography import x509\n\n            from cryptography.hazmat.backends.openssl import backend\n\n            from cryptography.hazmat.primitives import serialization\n\n            from cryptography.hazmat.primitives.serialization import pkcs12\n\n            import cryptography_vectors\n\n\n\n            path = os.path.join(\'x509\', \'custom\', \'ca\', \'ca.pem\')\n\n            with cryptography_vectors.open_vector_file(path, "rb") as f:\n\n                cert = x509.load_pem_x509_certificate(\n\n                    f.read(), backend\n\n                )\n\n            path2 = os.path.join(\'x509\', \'custom\', \'dsa_selfsigned_ca.pem\')\n\n            with cryptography_vectors.open_vector_file(path2, "rb") as f:\n\n                cert2 = x509.load_pem_x509_certificate(\n\n                    f.read(), backend\n\n                )\n\n            path3 = os.path.join(\'x509\', \'letsencryptx3.pem\')\n\n            with cryptography_vectors.open_vector_file(path3, "rb") as f:\n\n                cert3 = x509.load_pem_x509_certificate(\n\n                    f.read(), backend\n\n                )\n\n            key_path = os.path.join("x509", "custom", "ca", "ca_key.pem")\n\n            with cryptography_vectors.open_vector_file(key_path, "rb") as f:\n\n                key = serialization.load_pem_private_key(\n\n                    f.read(), None, backend\n\n                )\n\n            encryption = serialization.NoEncryption()\n\n            pkcs12.serialize_key_and_certificates(\n\n                b"name", key, cert, [cert2, cert3], encryption)\n\n        '))
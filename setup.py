#!/usr/bin/env python
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import os
import platform
import sys

from setuptools import setup

try:
    from setuptools_rust import RustExtension
except ImportError:
    print('\n\n        =============================DEBUG ASSISTANCE==========================\n\n        If you are seeing an error here please try the following to\n\n        successfully install cryptography:\n\n\n\n        Upgrade to the latest pip and try again. This will fix errors for most\n\n        users. See: https://pip.pypa.io/en/stable/installing/#upgrading-pip\n\n        =============================DEBUG ASSISTANCE==========================\n\n        ')
    raise
base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, 'src')
# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)
try:
    # See setup.cfg for most of the config metadata.
    # Enable abi3 mode if we're not using PyPy.
    setup(cffi_modules=['src/_cffi_src/build_openssl.py:ffi'], rust_extensions=[RustExtension('_rust', 'src/rust/Cargo.toml', py_limited_api=True, features=[] if platform.python_implementation() == 'PyPy' else ['pyo3/abi3-py36'], rust_version='>=1.41.0')])
except:  # noqa: E722
    # Note: This is a bare exception that re-raises so that we don't interfere
    # with anything the installation machinery might want to do. Because we
    # print this for any exception this msg can appear (e.g. in verbose logs)
    # even if there's no failure. For example, SetupRequirementsError is raised
    # during PEP517 building and prints this text. setuptools raises SystemExit
    # when compilation fails right now, but it's possible this isn't stable
    # or a public API commitment so we'll remain ultra conservative.
    import pkg_resources
    print('\n\n    =============================DEBUG ASSISTANCE=============================\n\n    If you are seeing a compilation error please try the following steps to\n\n    successfully install cryptography:\n\n    1) Upgrade to the latest pip and try again. This will fix errors for most\n\n       users. See: https://pip.pypa.io/en/stable/installing/#upgrading-pip\n\n    2) Read https://cryptography.io/en/latest/installation/ for specific\n\n       instructions for your platform.\n\n    3) Check our frequently asked questions for more information:\n\n       https://cryptography.io/en/latest/faq/\n\n    4) Ensure you have a recent Rust toolchain installed:\n\n       https://cryptography.io/en/latest/installation/#rust\n\n    ')
    print(f"    Python: {'.'.join((str(v) for v in sys.version_info[:3]))}")
    print(f'    platform: {platform.platform()}')
    for dist in ['pip', 'setuptools', 'setuptools_rust']:
        try:
            version = pkg_resources.get_distribution(dist).version
        except pkg_resources.DistributionNotFound:
            version = 'n/a'
        print(f'    {dist}: {version}')
    print('\n    =============================DEBUG ASSISTANCE=============================\n\n    ')
    raise
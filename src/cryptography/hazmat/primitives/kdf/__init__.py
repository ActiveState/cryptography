# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
import abc

class KeyDerivationFunction(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def derive(self, key_material):
        """

        Deterministically generates and returns a new key based on the existing

        key material.

        """

    @abc.abstractmethod
    def verify(self, key_material, expected_key):
        """

        Checks whether the key generated by the key material matches the

        expected derived key. Raises an exception if they do not match.

        """
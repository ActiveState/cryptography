# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import abc
import six


# This exists to break an import cycle. It is normally accessible from the
# ciphers module.


@six.add_metaclass(abc.ABCMeta)
class CipherAlgorithm(object):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this mode (e.g. "AES", "Camellia").
        """

    @abc.abstractproperty
    def key_sizes(self):
        """
        Valid key sizes for this algorithm in bits
        """

    @abc.abstractproperty
    def key_size(self):
        """
        The size of the key being used as an integer in bits (e.g. 128, 256).
        """


@six.add_metaclass(abc.ABCMeta)
class BlockCipherAlgorithm(object):
    @abc.abstractproperty
    def block_size(self):
        """
        The size of a block as an integer in bits (e.g. 64, 128).
        """

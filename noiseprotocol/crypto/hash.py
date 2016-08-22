#!/usr/bin/env python

import hmac

from hashlib import sha256, sha512

from pyblake2 import blake2s, blake2b


class HashFunction(object):

    def hash(self, data):
        return self._backend(data).digest()

    def hkdf(self, chaining_key, input_key_material):
        def hmac_(k, data):
            return hmac.new(k, data, self._backend).digest()
        temp_key = hmac_(chaining_key, input_key_material)
        output1 = hmac_(temp_key, '\x01')
        output2 = hmac_(temp_key, output1 + '\x02')
        return (output1, output2)


class SHA256(HashFunction):

    name = 'SHA256'

    def __init__(self):
        self._backend = sha256

    digest_size = 32


class SHA512(HashFunction):

    name = 'SHA512'

    def __init__(self):
        self._backend = sha512

    digest_size = 64


class BLAKE2b(HashFunction):

    name = 'BLAKE2b'

    def __init__(self):
        self._backend = blake2b

    digest_size = 64


class BLAKE2s(HashFunction):

    name = 'BLAKE2s'

    def __init__(self):
        self._backend = blake2s

    digest_size = 32

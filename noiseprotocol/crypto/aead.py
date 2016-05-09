#!/usr/bin/env python

# ChaCha and Poly1305 code courtesy and Copyright (c) 2015 Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

from __future__ import division

from struct import pack, unpack

try:
    # in Python 3 the native zip returns iterator
    from itertools import izip
except ImportError:
    izip = zip

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.exceptions import InvalidTag as _InvalidTag

class InvalidTag(Exception):
    pass

class AEADCipher(object):

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError('Invalid key size (32) for AES.')

        self.key = key

    @property
    def name(self):
        return self.__class__.__name__


class AESGCM(AEADCipher):
    '''
       AES256-GCM from NIST SP 800-38D with 128-bit tags. The 96-bit nonce is formed by encoding
       32 bits of zeros followed by big-endian encoding of n.
    '''

    @staticmethod
    def nonce(n):
        '''
           Cona 96-byte nonce where leading 32-bits are 0 and the trailing 64-bits is the
           value n encoded as a big-endian value.
        '''

        return '\x00\x00\x00\x00' + pack('>Q', n)

    def encrypt(self, n, ad, plaintext):
        '''
           Encrypts and returns concatenation of authentication tag and ciphertext.
        '''

        if len(n) != 12:
            raise ValueError("Nonce must be 96 bit large")

        encryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(n, min_tag_length=16),
            backend=default_backend()
        ).encryptor()

        encryptor.authenticate_additional_data(ad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return ciphertext + encryptor.tag

    def decrypt(self, n, ad, ciphertext):
        '''
           Returns plaintext or raises InvalidTag exception if fail to authenticate.
        '''

        if len(n) != 12:
            raise ValueError("Nonce must be 96 bit large")

        if len(ciphertext) < 16:
            raise ValueError(
                'Invalid ciphertext length (len={0}), must be >16 bytes.'.format(len(ciphertext))
            )

        decryptor = Cipher(
            algorithms.AES(self.key),
            modes.GCM(n, ciphertext[-16:]),
            backend=default_backend()
        ).decryptor()

        decryptor.authenticate_additional_data(ad)
        try:
            plaintext = decryptor.update(ciphertext[:-16]) + decryptor.finalize()
        except _InvalidTag:
            raise InvalidTag
        except:
            raise

        return plaintext


class ChaChaPoly(AEADCipher):
    '''
       AEAD_CHACHA20_POLY1305 from RFC 7539. The 96-bit nonce is formed by encoding 32 bits of
       zeros followed by little-endian encoding of n. (Earlier implementations of ChaCha20 used
       a 64-bit nonce, in which case it's compatible to encode n directly into the ChaCha20 nonce
       without the 32-bit zero prefix).
    '''

    @staticmethod
    def nonce(n):
        '''
           Construct a 96-byte nonce where leading 32-bits are 0 and the trailing 64-bits is the
           value n encoded as a little-endian value.
        '''

        return '\x00\x00\x00\x00' + pack('<Q', n)

    @staticmethod
    def _pad16(data):
        """Return padding for the Associated Authenticated Data"""
        if len(data) % 16 == 0:
            return bytearray(0)
        else:
            return bytearray(16 - (len(data) % 16))

    def _poly1305_gen_key(self, nonce):
        """Generate the key for the Poly1305 authenticator"""
        poly = _ChaCha(self.key, nonce)
        return poly.encrypt(bytearray(32))

    def encrypt(self, n, ad, plaintext):
        '''
           Encrypts and returns concatenation of authentication tag and ciphertext.
        '''

        if len(n) != 12:
            raise ValueError("Nonce must be 96 bit large")

        otk = self._poly1305_gen_key(n)

        ciphertext = _ChaCha(self.key, n, counter=1).encrypt(bytearray(plaintext))

        mac_data = ad + self._pad16(ad)
        mac_data += ciphertext + self._pad16(ciphertext)
        mac_data += pack('<Q', len(ad))
        mac_data += pack('<Q', len(ciphertext))
        tag = _Poly1305(otk).create_tag(mac_data)

        return str(ciphertext + tag)

    def decrypt(self, n, ad, ciphertext):
        '''
           Returns plaintext or raises InvalidTag exception if fail to authenticate.
        '''

        if len(n) != 12:
            raise ValueError("Nonce must be 96 bit long")

        if len(ciphertext) < 16:
            raise ValueError(
                'Invalid ciphertext length (len={0}), must be >16 bytes.'.format(len(ciphertext))
            )

        expected_tag = bytearray(ciphertext[-16:])
        ciphertext = bytearray(ciphertext[:-16])

        otk = self._poly1305_gen_key(n)

        mac_data = ad + self._pad16(ad)
        mac_data += ciphertext + self._pad16(ciphertext)
        mac_data += pack('<Q', len(ad))
        mac_data += pack('<Q', len(ciphertext))
        tag = _Poly1305(otk).create_tag(mac_data)

        if tag != expected_tag:
            raise InvalidTag

        return str(_ChaCha(self.key, n, counter=1).decrypt(ciphertext))


class _ChaCha(object):

    """Pure python implementation of ChaCha cipher"""

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 16) & 0xffffffff | (xd >> 16))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 12) & 0xffffffff | (xb >> 20))

        xa = (xa + xb) & 0xffffffff
        xd = xd ^ xa
        xd = ((xd << 8) & 0xffffffff | (xd >> 24))

        xc = (xc + xd) & 0xffffffff
        xb = xb ^ xc
        xb = ((xb << 7) & 0xffffffff | (xb >> 25))

        x[a] = xa
        x[b] = xb
        x[c] = xc
        x[d] = xd

    _round_mixup_box = [(0, 4, 8, 12),
                        (1, 5, 9, 13),
                        (2, 6, 10, 14),
                        (3, 7, 11, 15),
                        (0, 5, 10, 15),
                        (1, 6, 11, 12),
                        (2, 7, 8, 13),
                        (3, 4, 9, 14)]

    @classmethod
    def double_round(cls, x):
        """Perform two rounds of ChaCha cipher"""
        for a, b, c, d in cls._round_mixup_box:
            xa = x[a]
            xb = x[b]
            xc = x[c]
            xd = x[d]

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 16) & 0xffffffff | (xd >> 16))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 12) & 0xffffffff | (xb >> 20))

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 8) & 0xffffffff | (xd >> 24))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 7) & 0xffffffff | (xb >> 25))

            x[a] = xa
            x[b] = xb
            x[c] = xc
            x[d] = xd

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        state = _ChaCha.constants + key + [counter] + nonce

        working_state = state[:]
        dbl_round = _ChaCha.double_round
        for _ in range(0, rounds // 2):
            dbl_round(working_state)

        return [(st + wrkSt) & 0xffffffff for st, wrkSt
                in izip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        return bytearray(pack('<LLLLLLLLLLLLLLLL', *state))

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        ret = []
        for i in range(0, len(data)//4):
            ret.extend(unpack('<L', data[i*4:(i+1)*4]))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds

        # convert bytearray key and nonce to little endian 32 bit unsigned ints
        self.key = _ChaCha._bytearray_to_words(key)
        self.nonce = _ChaCha._bytearray_to_words(nonce)

    def encrypt(self, plaintext):
        """Encrypt the data"""

        encrypted_message = bytearray()
        for i, block in enumerate(plaintext[i:i+64] for i
                                  in range(0, len(plaintext), 64)):
            key_stream = _ChaCha.chacha_block(self.key,
                                             self.counter + i,
                                             self.nonce,
                                             self.rounds)
            key_stream = _ChaCha.word_to_bytearray(key_stream)
            encrypted_message += bytearray(x ^ y for x, y
                                           in izip(key_stream, block))

        return encrypted_message

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)


class _Poly1305(object):
    """Implementation of Poly1305 authenticator for RFC 7539"""

    P = 0x3fffffffffffffffffffffffffffffffb  # 2^130-5

    @staticmethod
    def le_bytes_to_num(data):
        """Convert a number from little endian byte format"""
        ret = 0
        for i in range(len(data) - 1, -1, -1):
            ret <<= 8
            ret += data[i]
        return ret

    @staticmethod
    def num_to_16_le_bytes(num):
        """Convert number to 16 bytes in little endian format"""
        ret = [0]*16
        for i, _ in enumerate(ret):
            ret[i] = num & 0xff
            num >>= 8
        return bytearray(ret)

    @staticmethod
    def divceil(divident, divisor):
        """Integer division with rounding up"""
        quot, r = divmod(divident, divisor)
        return quot + int(bool(r))

    def __init__(self, key):
        """Set the authenticator key"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        self.acc = 0
        self.r = self.le_bytes_to_num(key[0:16])
        self.r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.s = self.le_bytes_to_num(key[16:32])

    def create_tag(self, data):
        """Calculate authentication tag for data"""
        for i in range(0, self.divceil(len(data), 16)):
            n = self.le_bytes_to_num(data[i*16:(i+1)*16] + b'\x01')
            self.acc += n
            self.acc = (self.r * self.acc) % self.P
        self.acc += self.s
        return self.num_to_16_le_bytes(self.acc)

#!/usr/bin/env python

from struct import pack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.exceptions import InvalidTag


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
           Construct a 96-byte nonce where leading 32-bits are 0 and the trailing 64-bits is the
           value n encoded as a big-endian value.
        '''

        return '\x00\x00\x00\x00' + pack('>Q', n)

    def encrypt(self, n, ad, plaintext):
        '''
           Encrypts and returns concatenation of authentication tag and ciphertext.
        '''
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
        except InvalidTag:
            raise
        except:
            raise

        return plaintext

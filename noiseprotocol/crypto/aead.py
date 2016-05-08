#!/usr/bin/env python

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

def aes_gcm_encrypt(k, n, ad, plaintext):
    '''
       AES256-GCM from NIST SP 800-38D with 128-bit tags. The 96-bit nonce is formed by encoding
       32 bits of zeros followed by big-endian encoding of n.

       Returns concatenation of authentication tag and ciphertext.
    '''

    if len(k) != 32:
        raise ValueError('Invalid key size (32) for AES.')

    encryptor = Cipher(
        algorithms.AES(k),
        modes.GCM(n, min_tag_length=16),
        backend=default_backend()
    ).encryptor()

    encryptor.authenticate_additional_data(ad)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext + encryptor.tag

def aes_gcm_decrypt(k, n, ad, ciphertext):
    '''
       AES256-GCM from NIST SP 800-38D with 128-bit tags. The 96-bit nonce is formed by encoding
       32 bits of zeros followed by big-endian encoding of n.

       Returns plaintext or raises InvalidTag exception if fail to authenticate.
    '''

    if len(k) != 32:
        raise ValueError('Invalid key size (32) for AES.')

    if len(ciphertext) < 16:
        raise ValueError('Invalid ciphertext size ({0}), must be >16 bytes.'.format(len(ciphertext)))

    decryptor = Cipher(
        algorithms.AES(k),
        modes.GCM(n, ciphertext[-16:]),
        backend=default_backend()
    ).decryptor()

    decryptor.authenticate_additional_data(ad)
    plaintext = decryptor.update(ciphertext[:-16]) + decryptor.finalize()

    return plaintext

#!/usr/bin/env python


class CipherState(object):

    def __init__(self, aead_cipher):
        self.k = None
        self.n = 0
        self.aead_cipher = aead_cipher

    def initialize(self, key):
        if len(key) != 32:
            raise ValueError('Invalid key size (32) for AEAD Cipher.')
        self.k = key
        self.n = 0

    def has_key(self):
        return self.k is not None

    def encrypt(self, ad, plaintext):
        if self.k is None:
            return plaintext

        ct = self.aead_cipher(self.k).encrypt(self.n, ad, plaintext)
        self.n += 1
        return ct

    def decrypt(self, ad, ciphertext):
        if self.k is None:
            return ciphertext

        pt = self.aead_cipher(self.k).decrypt(self.n, ad, ciphertext)
        self.n += 1
        return pt


class SymmetricState(object):
    def __init__(self, cipher_state, hash):
        self.cipher_state = cipher_state
        self.hash = hash()
        self.ck = None
        self.h = None

    def initialize(self, protocol_name):
        size = self.hash.digest_size
        if len(protocol_name) < size:
            self.h = protocol_name + '\x00'*(size - len(protocol_name))
        else:
            self.h = self.hash.hash(protocol_name)

    def mix_key(self, input_key_material):
        self.ck, temp = self.hash.hkdf(self.ck, input_key_material)
        if len(temp) > 32:
            temp = temp[0:32]
        self.cipher_state.initialize(temp)

    def mix_hash(self, data):
        self.h = self.hash.hash(self.h + data)

    def encrypt(self, plaintext):
        ct = self.cipher_state.encrypt(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt(self, ciphertext):
        pt = self.cipher_state.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self):
        temp_k1, temp_k2 = self.hash.hkdf(self.ck, '')
        if len(temp_k1) > 32:
            temp_k1 = temp_k1[0:32]
        if len(temp_k2) > 32:
            temp_k2 = temp_k2[0:32]
        c1 = CipherState(self.cipher_state.aead_cipher)
        c2 = CipherState(self.cipher_state.aead_cipher)
        c1.initialize(temp_k1)
        c2.initialize(temp_k2)
        return (c1, c2)


# TODO...
class HandshakeState(object):
    def __init__(self, symmetric_state, dh):
        self.symmetric_state = symmetric_state
        self.dh = dh
        self.pattern = None
        self.s = None
        self.e = None
        self.rs = None
        self.re = None

    def initialize(self, handshake_pattern, initiator, prologue, s, e, rs, re, psk=None):
        # TODO....
        cipher_name = self.symmetric_state.cipher_state.aead_cipher.name
        hash_name = self.symmetric_state.hash.name

        self.s = s
        self.e = e
        self.rs = rs
        self.re = re
        self.psk = psk

    def write_message(self, payload, message_buffer):
        # TODO ...

    def read_message(self, payload, message_buffer):
        # TODO ...


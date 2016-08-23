#!/usr/bin/env python

from pattern import Token


class InvalidState(Exception):
    pass


class CipherState(object):

    def __init__(self, aead_cipher):
        self.k = None
        self.n = 0
        self.cipher = aead_cipher

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

        ct = self.cipher(self.k).encrypt(self.n, ad, plaintext)
        self.n += 1
        return ct

    def decrypt(self, ad, ciphertext):
        if self.k is None:
            return ciphertext

        # raises InvalidTag exception if decrypt fails
        pt = self.cipher(self.k).decrypt(self.n, ad, ciphertext)
        self.n += 1
        return pt

    def __eq__(self, other):
        return self.k == other.k and self.n == other.n


class SymmetricState(object):
    def __init__(self, cipher_state, hash):
        self.cs = cipher_state
        self.hash = hash()
        self.ck = None
        self.h = None

    def initialize(self, protocol_name):
        size = self.hash.digest_size
        if len(protocol_name) <= size:
            self.h = protocol_name + '\x00'*(size - len(protocol_name))
        else:
            self.h = self.hash.hash(protocol_name)

        self.ck = self.h

    def mix_key(self, input_key_material):
        self.ck, temp = self.hash.hkdf(self.ck, input_key_material)
        if len(temp) == 64:
            temp = temp[:32]
        self.cs.initialize(temp)

    def mix_hash(self, data):
        self.h = self.hash.hash(self.h + data)

    def encrypt_and_hash(self, plaintext):
        ct = self.cs.encrypt(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext):
        pt = self.cs.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def split(self):
        temp_k1, temp_k2 = self.hash.hkdf(self.ck, '')
        if len(temp_k1) == 64:
            temp_k1 = temp_k1[:32]
        if len(temp_k2) == 64:
            temp_k2 = temp_k2[:32]
        c1 = CipherState(self.cs.cipher)
        c2 = CipherState(self.cs.cipher)
        c1.initialize(temp_k1)
        c2.initialize(temp_k2)
        return (c1, c2)

    def __eq__(self, other):
        return self.cs == other.cs and self.ck == other.ck and self.h == other.h


class HandshakeState(object):
    def __init__(self, symmetric_state, dh):
        self.ss = symmetric_state
        self.dh = dh()
        self.pattern = None
        self.s = None
        self.e = None
        self.rs = None
        self.re = None

    def initialize(self, handshake_pattern, initiator, prologue='',
                   s=None, e=None, rs=None, re=None, psk=None):
        prefix = "Noise"
        if psk and len(psk) > 0:
            prefix = "Noise_PSK"

        cipher_name = self.ss.cs.cipher.name
        hash_name = self.ss.hash.name
        dh_name = self.dh.name

        protocol_name = '_'.join([prefix, handshake_pattern.name, dh_name, cipher_name, hash_name])
        self.ss.initialize(protocol_name)
        self.ss.mix_hash(prologue)

        self.s = s
        self.e = e
        self.rs = rs
        self.re = re
        self.psk = psk
        self.initiator = initiator

        for t in handshake_pattern.initiator_premessages:
            if initiator and t == Token.S:
                self.ss.mix_hash(s.public)
            elif initiator and t == Token.E:
                self.ss.mix_hash(e.public)
            elif not initiator and t == Token.S:
                self.ss.mix_hash(rs)
            elif not initiator and t == Token.E:
                self.ss.mix_hash(re)

        for t in handshake_pattern.responder_premessages:
            if not initiator and t == Token.S:
                self.ss.mix_hash(s.public)
            elif not initiator and t == Token.E:
                self.ss.mix_hash(e.public)
            elif initiator and t == Token.S:
                self.ss.mix_hash(rs)
            elif initiator and t == Token.E:
                self.ss.mix_hash(re)

        self.patterns = list(handshake_pattern.messages)

    def write_message(self, payload):
        if not self.initiator:
            raise InvalidState("write_message called when not initiator")

        message_buffer = ""

        while len(self.patterns) > 0:
            p = self.patterns.pop(0)

            if p == Token.E:
                self.e = self.dh.generate_keypair()
                self.ss.mix_hash(self.e.public)
                message_buffer += self.e.public
            elif p == Token.S:
                message_buffer += self.ss.encrypt_and_hash(self.s.public_key)
            elif p == Token.DHEE:
                self.ss.mix_key(self.dh.dh(self.e, self.re))
            elif p == Token.DHES:
                self.ss.mix_key(self.dh.dh(self.e, self.rs))
            elif p == Token.DHSE:
                self.ss.mix_key(self.dh.dh(self.s, self.re))
            elif p == Token.DHSS:
                self.ss.mix_key(self.dh.dh(self.s, self.rs))
            elif p == Token.SWAP:
                # we're done
                break

        message_buffer += self.ss.encrypt_and_hash(payload)

        c1, c2 = None, None
        if len(self.patterns) == 0:
            c1, c2 = self.ss.split()

        self.initiator = False
        return message_buffer, c1, c2

    def read_message(self, message):
        if self.initiator:
            raise InvalidState("read_message called when initiator")

        buf = message

        while len(self.patterns) > 0:
            p = self.patterns.pop(0)

            if p == Token.E:
                self.re = buf[:self.dh.dhlen]
                buf = buf[self.dh.dhlen:]
                self.ss.mix_hash(self.re)
            elif p == Token.S:
                if self.ss.cs.has_key():
                    temp = buf[:self.dh.dhlen+16]
                    buf = buf[self.dh.dhlen+16:]
                else:
                    temp = buf[:self.dh.dhlen]
                    buf = buf[self.dh.dhlen:]
                self.rs = self.ss.decrypt_and_hash(temp)
            elif p == Token.DHEE:
                self.ss.mix_key(self.dh.dh(self.e, self.re))
            elif p == Token.DHES:
                self.ss.mix_key(self.dh.dh(self.e, self.rs))
            elif p == Token.DHSE:
                self.ss.mix_key(self.dh.dh(self.s, self.re))
            elif p == Token.DHSS:
                self.ss.mix_key(self.dh.dh(self.s, self.rs))
            elif p == Token.SWAP:
                # we're done
                break

        payload_buffer = self.ss.decrypt_and_hash(buf)

        c1, c2 = None, None
        if len(self.patterns) == 0:
            c1, c2 = self.ss.split()

        self.initiator = True
        return payload_buffer, c1, c2

#!/usr/bin/env python

from state import CipherState, SymmetricState, HandshakeState
import os

def NoiseHandshake(aead_cipher, hash, dh, rng=os.urandom):
    """ Create a HandshakeState for executing a noise protocol """

    cs = CipherState(aead_cipher)
    ss = SymmetricState(cs, hash)
    hs = HandshakeState(ss, dh, rng)
    return hs

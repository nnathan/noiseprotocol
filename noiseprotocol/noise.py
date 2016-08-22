#!/usr/bin/env python

from state import CipherState, SymmetricState, HandshakeState

def NoiseHandshake(aead_cipher, hash, dh):
    """ Create a HandshakeState for executing a noise protocol """

    cs = CipherState(aead_cipher)
    ss = SymmetricState(cs, hash)
    hs = HandshakeState(ss, dh)
    return hs

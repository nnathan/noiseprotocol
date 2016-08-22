#!/usr/bin/env python

import json
from binascii import unhexlify as unhex, hexlify as hex

from noiseprotocol.crypto.aead import *
from noiseprotocol.crypto.hash import *
from noiseprotocol.crypto.dh import *
from noiseprotocol.pattern import *
from noiseprotocol.noise import *

def mock_curve(name):
    if name == '25519':
        class Curve25519_test(Curve25519):
            def generate_keypair(self):
                pub = c25519_scalarmult_base(self.priv)
                return DHKeyPair(self.priv, pub)

        return Curve25519_test
    elif name == '448':
        class Curve448_test(Curve448):
            def generate_keypair(self):
                pub = c448_scalarmult_base(self.priv)
                return DHKeyPair(self.priv, pub)

        return Curve448_test


def doit(v):
    name = v['name']
    aead = globals()[v['cipher']]
    init_dh = mock_curve(v['dh'])
    resp_dh = mock_curve(v['dh'])
    hash = globals()[v['hash']]
    pattern = globals()['Noise_'+v['pattern']]
    prefix = 'Noise'
    assert name == '_'.join([prefix, pattern.name, init_dh.name, aead.name, hash.name])
    init_prologue = unhex(v.get('init_prologue'))
    resp_prologue = unhex(v.get('resp_prologue'))
    # sanity check
    assert init_prologue == resp_prologue

    init_ephemeral = unhex(v.get('init_ephemeral'))
    init_dh.priv = init_ephemeral
    resp_ephemeral = unhex(v.get('resp_ephemeral'))
    resp_dh.priv = init_ephemeral

    alice = NoiseHandshake(aead, hash, init_dh)
    bob = NoiseHandshake(aead, hash, resp_dh)
    p = unhex(v['messages'][0]['payload'])
    alice.initialize(pattern, True, init_prologue, None, None, None, None, None)
    out, c1, c2 = alice.write_message(p)
    print hex(out)


j = json.load(open('cacaphony.txt'))

doit(j['vectors'][0])

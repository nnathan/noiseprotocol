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
    init_prologue = v.get('init_prologue')
    resp_prologue = v.get('resp_prologue')
    # sanity check
    assert init_prologue == resp_prologue

    init_ephemeral = unhex(v.get('init_ephemeral'))
    init_dh.priv = init_ephemeral
    resp_ephemeral = unhex(v.get('resp_ephemeral'))
    resp_dh.priv = resp_ephemeral

    init, resp = NoiseHandshake(aead, hash, init_dh), NoiseHandshake(aead, hash, resp_dh)

    init.Initialize(pattern, True, init_prologue, None, None, None, None)
    resp.Initialize(pattern, False, resp_prologue, None, None, None, None)

    for m in v['messages']:
        print m
        ct = unhex(m['ciphertext'])
        payload = unhex(m.get('payload', ''))
        out1, ic1, ic2 = init.WriteMessage(payload)
        print "ct:\t{0}".format(hex(ct))
        print "out1:\t{0}".format(hex(out1))
        assert out1 == ct
        out2, rc1, rc2 = resp.ReadMessage(out1)
        print "out2:\t{0}".format(hex(out2))
        init, resp = resp, init

j = json.load(open('cacaphony.txt'))

doit(j['vectors'][0])

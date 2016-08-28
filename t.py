#!/usr/bin/env python

import json
from binascii import unhexlify, hexlify as hex

from noiseprotocol.crypto.aead import *
from noiseprotocol.crypto.hash import *
from noiseprotocol.crypto.dh import *
from noiseprotocol.pattern import *
from noiseprotocol.noise import *

def unhex(s):
    if s == None:
        return None
    else:
        return unhexlify(s)

def doit(v):
    print v['name']
    if 'SSK' in v['name']:
        return
    name = v['name']
    aead = globals()[v['cipher']]
    init_dh = globals()['Curve'+v['dh']]
    resp_dh = globals()['Curve'+v['dh']]
    hash = globals()[v['hash']]
    pattern = globals()['Noise_'+v['pattern']]
    one_way = False
    if v['pattern'] in [ 'N', 'X', 'K' ]:
        one_way = True

    prefix = 'Noise'
    if v.get('init_psk', None) is not None:
        prefix += 'PSK'
    assert name == '_'.join([prefix, pattern.name, init_dh.name, aead.name, hash.name])

    init_prologue = unhex(v.get('init_prologue'))
    resp_prologue = unhex(v.get('resp_prologue'))
    init_ephemeral = unhex(v.get('init_ephemeral'))
    resp_ephemeral = unhex(v.get('resp_ephemeral'))

    init_psk = unhex(v.get('init_psk', None))
    resp_psk = unhex(v.get('resp_psk', None))

    init_static = unhex(v.get('init_static', None))
    resp_static = unhex(v.get('resp_static', None))
    if init_static is not None:
        dh = init_dh(lambda x: init_static)
        init_static = dh.generate_keypair()
    if resp_static is not None:
        dh = resp_dh(lambda x: resp_static)
        dh.priv = resp_static
        resp_static = dh.generate_keypair()
    init_semiephemeral = unhex(v.get('init_semiephemeral', None))
    resp_semiephemeral = unhex(v.get('resp_semiephemeral', None))
    init_remote_static = unhex(v.get('init_remote_static', None))
    resp_remote_static = unhex(v.get('resp_remote_static', None))
    init_remote_semiephemeral = unhex(v.get('init_remote_semiephemeral', None))
    resp_remote_semiephemeral = unhex(v.get('resp_remote_semiephemeral', None))

    init = NoiseHandshake(aead, hash, init_dh, lambda x: init_ephemeral)
    resp = NoiseHandshake(aead, hash, resp_dh, lambda y: resp_ephemeral)

    init.Initialize(pattern, True, init_prologue, init_static, init_semiephemeral, init_remote_static, init_remote_semiephemeral, init_psk)
    resp.Initialize(pattern, False, resp_prologue, resp_static, resp_semiephemeral, resp_remote_static, resp_remote_semiephemeral, resp_psk)

    send, recv = init, resp

    messages = v['messages']
    while len(messages) > 0:
        m = messages.pop(0)
        ct = unhex(m['ciphertext'])
        print "ct:\t{0}".format(hex(ct))
        payload = unhex(m.get('payload', ''))
        print "p:\t{0}".format(hex(payload))
        iout, ic1, ic2 = send.WriteMessage(payload)
        assert ct == iout
        print "iout:\t{0}".format(hex(iout))
        rout, rc1, rc2 = recv.ReadMessage(iout)
        print "rout:\t{0}".format(hex(rout))
        send, recv = recv, send
        if ic1 is not None and ic2 is not None and rc1 is not None and rc2 is not None:
            break

    if resp.initiator and not one_way:
        ic2, ic1, rc2, rc1 = rc1, rc2, ic1, ic2
    for m in messages: 
        ct = unhex(m['ciphertext'])
        print "ct:\t{0}".format(hex(ct))
        payload = unhex(m.get('payload', ''))
        print "p:\t{0}".format(hex(payload))
        iout = ic1.EncryptWithAd('', payload)
        print "iout:\t{0}".format(hex(iout))
        rout = rc1.DecryptWithAd('', iout)
        assert ct == iout
        if not one_way:
            ic2, ic1, rc2, rc1 = rc1, rc2, ic1, ic2

j = json.load(open('cacaphony.txt'))
#j = json.load(open('z'))

for v in j['vectors']:
    doit(v)

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.constants import *
from lib.dependency import *
from lib.ECDSA_constants import *
from model.key import *

class tx():
    def __init__(self):
        self.ins = []
        self.pubkey = []
        self.tosign = False

    def hashtypeone(self, index, script):
        global empty_txin
        for i in range(len(self.ins)):
            self.ins[i] = empty_txin
        self.ins[index]['pubkey'] = ""
        self.ins[index]['oldscript'] = s
        self.tosign = True

    def copy(self):
        r = tx()
        r.ins = self.ins[:]
        r.outs = self.outs[:]
        return r

    def sign(self, n=-1):
        if n == -1:
            for i in range(len(self.ins)):
                self.sign(i)
                return "done"

        global json_db
        txcopy = self.copy()
        txcopy.hashtypeone(i, self.ins[n]['oldscript'])

        sec = ''
        for k in json_db['keys']:
            if k['addr'] == self.ins[n]['addr'] and 'hexsec' in k:
                sec = k['hexsec']
        if sec == '':
            print "priv key not found (addr:" + self.ins[n]['addr'] + ")"
            return ""

        self.ins[n]['sig'] = sign_message(sec.decode('hex'), txcopy.get_tx(), True)

    def ser(self):
        r = {}
        r['ins'] = self.ins
        r['outs'] = self.outs
        r['tosign'] = self.tosign
        return json.dumps(r)

    def unser(self, r):
        s = json.loads(r)
        self.ins = s['ins']
        self.outs = s['outs']
        self.tosign = s['tosign']

    def get_tx(self):
        r = ''
        ret += inverse_str("%08x" % 1)
        ret += "%02x" % len(self.ins)

        for i in range(len(self.ins)):
            txin = self.ins[i]
            ret += inverse_str(txin['hash'])
            ret += inverse_str("%08x" % txin['index'])

            if txin['pubkey'] != "":
                tmp += "%02x" % (1 + len(txin['sig']) / 2)
                tmp += txin['sig']
                tmp += "01"
                tmp += "%02x" % (len(txin['pubkey']) / 2)
                tmp += txin['pubkey']

                ret += "%02x" % (len(tmp) / 2)
                ret += tmp

            elif txin['oldscript'] != "":
                ret += "%02x" % (len(txin['oldscript']) / 2)
                ret += txin['oldscript']

            else:
                ret += "00"

            ret += "ffffffff"

        ret += "%02x" % len(self.outs)

        for i in range(len(self.outs)):
            txout = self.outs[i]
            ret += inverse_str("%016x" % (txout['amount']))

            if txout['script'][:2] == 's:':  # script
                script = txout['script'][:2]
                ret += "%02x" % (len(script) / 2)
                ret += script
            else:  # address
                ret += "%02x" % (len(txout['script']) / 2 + 5)
                ret += "%02x" % OP_DUP
                ret += "%02x" % OP_HASH160
                ret += "%02x" % (len(txout['script']) / 2)
                ret += txout['script']
                ret += "%02x" % OP_EQUALVERIFY
                ret += "%02x" % OP_CHECKSIG

        ret += "00000000"
        if not self.tosign:
            ret += "01000000"
        return ret


def inverse_str(string):
    ret = ""
    for i in range(len(string) / 2):
        ret += string[len(string) - 2 - 2 * i];
        ret += string[len(string) - 2 - 2 * i + 1];
    return ret


def sign_message(secret, msg, msgIsHex=False):
    k = KEY()
    k.generate(secret)
    return k.sign(message_to_hash(msg, msgIsHex))


def verify_message_signature(pubkey, sign, msg, msgIsHex=False):
    k = KEY()
    k.set_pubkey(pubkey.decode('hex'))
    return k.verify(message_to_hash(msg, msgIsHex), sign.decode('hex'))



def message_to_hash(msg, msgIsHex=False):
    str = ""
    #	str += '04%064x%064x'%(pubkey.point.x(), pubkey.point.y())
    #	str += "Padding text - "
    str += msg
    if msgIsHex:
        str = str.decode('hex')
    hash = Hash(str)
    return hash

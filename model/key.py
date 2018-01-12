#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lib.ECDSA_constants import *
from model.ECDSA import *
from lib.ECDSA_constants import *
from model.hash import *


class KEY:
    def __init__(self):
        self.prikey = None
        self.pubkey = None

    def generate(self, secret=None):
        if secret:
            exp = int('0x' + secret.encode('hex'), 16)
            self.prikey = ecdsa.SigningKey.from_secret_exponent(exp, curve=secp256k1)
        else:
            self.prikey = ecdsa.SigningKey.generate(curve=secp256k1)
        self.pubkey = self.prikey.get_verifying_key()
        return self.prikey.to_der()

    def set_privkey(self, key):
        if len(key) == 279:
            seq1, rest = der.remove_sequence(key)
            integer, rest = der.remove_integer(seq1)
            octet_str, rest = der.remove_octet_string(rest)
            tag1, cons1, rest, = der.remove_constructed(rest)
            tag2, cons2, rest, = der.remove_constructed(rest)
            point_str, rest = der.remove_bitstring(cons2)
            self.prikey = ecdsa.SigningKey.from_string(octet_str, curve=secp256k1)
        else:
            self.prikey = ecdsa.SigningKey.from_der(key)

    def set_pubkey(self, key):
        key = key[1:]
        self.pubkey = ecdsa.VerifyingKey.from_string(key, curve=secp256k1)

    def get_privkey(self):
        _p = self.prikey.curve.curve.p()
        _r = self.prikey.curve.generator.order()
        _Gx = self.prikey.curve.generator.x()
        _Gy = self.prikey.curve.generator.y()
        encoded_oid2 = der.encode_oid(*(1, 2, 840, 10045, 1, 1))
        encoded_gxgy = "\x04" + ("%64x" % _Gx).decode('hex') + ("%64x" % _Gy).decode('hex')
        param_sequence = der.encode_sequence(
            ecdsa.der.encode_integer(1),
            der.encode_sequence(
                encoded_oid2,
                der.encode_integer(_p),
            ),
            der.encode_sequence(
                der.encode_octet_string("\x00"),
                der.encode_octet_string("\x07"),
            ),
            der.encode_octet_string(encoded_gxgy),
            der.encode_integer(_r),
            der.encode_integer(1),
        );
        encoded_vk = "\x00\x04" + self.pubkey.to_string()
        return der.encode_sequence(
            der.encode_integer(1),
            der.encode_octet_string(self.prikey.to_string()),
            der.encode_constructed(0, param_sequence),
            der.encode_constructed(1, der.encode_bitstring(encoded_vk)),
        )

    def get_pubkey(self):
        return "\x04" + self.pubkey.to_string()

    def sign(self, hash):
        sig = self.prikey.sign_digest(hash, sigencode=ecdsa.util.sigencode_der)
        return sig.encode('hex')

    def verify(self, hash, sig):
        return self.pubkey.verify_digest(sig, hash, sigdecode=ecdsa.util.sigdecode_der)


# hexprivate key to encodedbase58
def SecretToASecret(secret, compressed=False):
    # 主要用来表示ascii码对应的字符他的输入时数字
    prefix = chr((addrtype + 128) & 255)
    # if addrtype == 48:  # assuming Litecoin
    #     prefix = chr(128)
    vchIn = prefix + secret
    if compressed: vchIn += '\01'
    return EncodeBase58Check(vchIn)


def ASecretToSecret(sec):
    vch = DecodeBase58Check(sec)
    if not vch:
        return False
    if vch[0] != chr((addrtype + 128) & 255):
        print 'Warning: adress prefix seems bad (%d vs %d)' % (ord(vch[0]), (addrtype + 128) & 255)
    return vch[1:]


def regenerate_key(sec):
    b = ASecretToSecret(sec)
    if not b:
        return False
    b = b[0:32]
    secret = int('0x' + b.encode('hex'), 16)
    return EC_KEY(secret)


def GetPubKey(pkey, compressed=False):
    return i2o_ECPublicKey(pkey, compressed)


def GetPrivKey(pkey, compressed=False):
    return i2d_ECPrivateKey(pkey, compressed)


# pkey.secret Hexprivkey
def GetSecret(pkey):
    # print "before hex", ('%064x' % pkey.secret)
    return ('%064x' % pkey.secret).decode('hex')


def is_compressed(sec):
    b = ASecretToSecret(sec)
    return len(b) == 33


def long_hex(bytes):
    return bytes.encode('hex_codec')


def EncodeBase58Check(secret):
    hash = Hash(secret)
    return b58encode(secret + hash[0:4])

def DecodeBase58Check(sec):
    vchRet = b58decode(sec, None)
    secret = vchRet[0:-4]
    csum = vchRet[-4:]
    hash = Hash(secret)
    cs32 = hash[0:4]
    if cs32 != csum:
        return None
    else:
        return secret

def str_to_long(b):
    res = 0
    pos = 1
    for a in reversed(b):
        res += ord(a) * pos
        pos *= 256
    return res


def PrivKeyToSecret(privkey):
    if len(privkey) == 279:
        return privkey[9:9 + 32]
    else:
        return privkey[8:8 + 32]

def i2d_ECPrivateKey(pkey, compressed=False):  # , crypted=True):
    part3 = 'a081a53081a2020101302c06072a8648ce3d0101022100'  # for uncompressed keys
    if compressed:
        if True:  # not crypted:  ## Bitcoin accepts both part3's for crypted wallets...
            part3 = 'a08185308182020101302c06072a8648ce3d0101022100'  # for compressed keys
        key = '3081d30201010420' + \
              '%064x' % pkey.secret + \
              part3 + \
              '%064x' % _p + \
              '3006040100040107042102' + \
              '%064x' % _Gx + \
              '022100' + \
              '%064x' % _r + \
              '020101a124032200'
    else:
        key = '308201130201010420' + \
              '%064x' % pkey.secret + \
              part3 + \
              '%064x' % _p + \
              '3006040100040107044104' + \
              '%064x' % _Gx + \
              '%064x' % _Gy + \
              '022100' + \
              '%064x' % _r + \
              '020101a144034200'

    return key.decode('hex') + i2o_ECPublicKey(pkey, compressed)


'''
     public keys are 65 bytes long (520 bits)
     0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
     0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
     compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
     未压缩格式公钥使用04作为前缀，而压缩格式公钥是以02或03作为前缀。
'''


def i2o_ECPublicKey(pkey, compressed=False):
    if compressed:
        if pkey.pubkey.point.y() & 1:
            key = '03' + '%064x' % pkey.pubkey.point.x()
        else:
            key = '02' + '%064x' % pkey.pubkey.point.x()
    else:
        key = '04' + \
              '%064x' % pkey.pubkey.point.x() + \
              '%064x' % pkey.pubkey.point.y()

    return key.decode('hex')

def keyinfo(sec, keyishex, coin_type='Bitcoin'):
    global addrtype
    if coin_type is None:
        coin_type = 'Bitcoin'
    if len(get_keys(aversions, coin_type.capitalize())) is 0:
        print("please input an valid coin type e.g. bitcoin/litecoin")
        exit(0)
    else:
        addrtype = get_keys(aversions, coin_type.capitalize())[-1]

    if keyishex is None:
        pkey = regenerate_key(sec)
        compressed = is_compressed(sec)
    elif len(sec) == 64:
        pkey = EC_KEY(str_to_long(sec.decode('hex')))
        compressed = False
    elif len(sec) == 66:
        pkey = EC_KEY(str_to_long(sec[:-2].decode('hex')))
        compressed = True
    else:
        print("Hexadecimal private keys must be 64 or 66 characters long (specified one is " + str(
            len(sec)) + " characters long)")
        exit(0)

    if not pkey:
        return False

    secret = GetSecret(pkey)
    private_key = GetPrivKey(pkey, compressed)
    public_key = GetPubKey(pkey, compressed)
    addr = public_key_to_bc_address(public_key, addrtype)

    print "Address (%s): %s" % (aversions[addrtype], addr)
    print "Privkey (%s): %s" % (aversions[addrtype], SecretToASecret(secret, compressed))
    print "Hexprivkey:   %s" % secret.encode('hex')
    print "Hash160:      %s" % (bc_address_to_hash_160(addr).encode('hex'))

    return True



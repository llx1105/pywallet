#!/usr/bin/env python
# -*- coding: utf-8 -*-
###################################
# pywallet crypter implementation #
###################################

from lib.dependency import *
from model.AES import *
crypter = None

try:
    from Crypto.Cipher import AES
    crypter = 'pycrypto'
except:
    pass


class Crypter_pycrypto(object):
    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        data = vKeyData + vSalt
        for i in xrange(nDerivIterations):
            data = hashlib.sha512(data).digest()
        self.SetKey(data[0:32])
        self.SetIV(data[32:32 + 16])
        return len(data)

    def SetKey(self, key):
        self.chKey = key

    def SetIV(self, iv):
        self.chIV = iv[0:16]

    def Encrypt(self, data):
        return AES.new(self.chKey, AES.MODE_CBC, self.chIV).encrypt(append_PKCS7_padding(data))

    def Decrypt(self, data):
        return AES.new(self.chKey, AES.MODE_CBC, self.chIV).decrypt(data)[0:32]


# 模块ctypes是Python内建的用于调用动态链接库函数的功能模块
try:
    if not crypter:
        import ctypes
        import ctypes.util

        ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')
        crypter = 'ssl'
except:
    pass


class Crypter_ssl(object):
    def __init__(self):
        self.chKey = ctypes.create_string_buffer(32)
        self.chIV = ctypes.create_string_buffer(16)
        self.OPENSSL_ENC_MAGIC = b'Salted__'
        self.PKCS5_SALT_LEN = 8

    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        strKeyData = ctypes.create_string_buffer(vKeyData)
        chSalt = ctypes.create_string_buffer(vSalt)
        # EVP_BytesToKey(EVP_des_ede3_cbc,EVP_md5,NULL,passwd,strlen(passwd),key,iv);
        print "vkeyData:", vKeyData, "chSalt:", chSalt, "nDerivIterations:", nDerivIterations, "nDerivationMethod:", nDerivationMethod
        print "chKey:", ctypes.byref(self.chKey), "chIV", self.chIV
        return ssl.EVP_BytesToKey(ssl.EVP_aes_256_cbc(), ssl.EVP_sha512(), chSalt, strKeyData,
                                  len(vKeyData), 0, ctypes.byref(self.chKey), ctypes.byref(self.chIV))

    def SetKey(self, key):
        self.chKey = ctypes.create_string_buffer(key)

    def SetIV(self, iv):
        self.chIV = ctypes.create_string_buffer(iv)

    def Encrypt(self, data):
        buf = ctypes.create_string_buffer(len(data) + 16)
        written = ctypes.c_int(0)
        final = ctypes.c_int(0)
        ctx = ssl.EVP_CIPHER_CTX_new()
        ssl.EVP_CIPHER_CTX_init(ctx)
        ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
        ssl.EVP_EncryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
        output = buf.raw[:written.value]
        ssl.EVP_EncryptFinal_ex(ctx, buf, ctypes.byref(final))
        output += buf.raw[:final.value]
        return output

    def Decrypt(self, data):
        buf = ctypes.create_string_buffer(len(data) + 16)
        written = ctypes.c_int(0)
        final = ctypes.c_int(0)
        ctx = ssl.EVP_CIPHER_CTX_new()
        ssl.EVP_CIPHER_CTX_init(ctx)
        ssl.EVP_DecryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
        ssl.EVP_DecryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
        output = buf.raw[:written.value]
        ssl.EVP_DecryptFinal_ex(ctx, buf, ctypes.byref(final))
        output += buf.raw[:final.value]
        return output


class Crypter_pure(object):
    def __init__(self):
        self.m = AESModeOfOperation()
        self.cbc = self.m.modeOfOperation["CBC"]
        self.sz = self.m.aes.keySize["SIZE_256"]

    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        data = vKeyData + vSalt
        # sha512 nDerivIterations times
        for i in xrange(nDerivIterations):
            data = hashlib.sha512(data).digest()
        self.SetKey(data[0:32])
        self.SetIV(data[32:32 + 16])
        return len(data)

    def SetKey(self, key):
        self.chKey = [ord(i) for i in key]

    def SetIV(self, iv):
        self.chIV = [ord(i) for i in iv]

    def Encrypt(self, data):
        mode, size, cypher = self.m.encrypt(append_PKCS7_padding(data), self.cbc, self.chKey, self.sz, self.chIV)
        return ''.join(map(chr, cypher))

    def Decrypt(self, data):
        chData = [ord(i) for i in data]
        return self.m.decrypt(chData, self.sz, self.cbc, self.chKey, self.sz, self.chIV)


if crypter == 'pycrypto':
    crypter = Crypter_pycrypto()
# print "Crypter: pycrypto"
elif crypter == 'ssl':
    crypter = Crypter_ssl()
# print "Crypter: ssl"
else:
    crypter = Crypter_pure()
    #	print "Crypter: pure"
    logging.warning("pycrypto or libssl not found, decryption may be slow")

    ##########################################
    # end of pywallet crypter implementation #
    ##########################################
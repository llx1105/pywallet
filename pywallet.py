#!/usr/bin/env python

# pywallet.py 1.1
# based on http://github.com/gavinandresen/bitcointools
#

from bsddb.db import *
import os, sys, time
import json
import logging
import struct
import StringIO
import traceback
import socket
import types
import string
import exceptions
import hashlib
import random
import urllib

from twisted.internet import reactor
from twisted.web import server, resource
from twisted.web.static import File
from twisted.python import log
from datetime import datetime

from subprocess import *

max_version = 32500
addrtype = 0
json_db = {}
private_keys = []
private_hex_keys = []
balance_site = 'http://bitcoin.site50.net/balance.php?adresse'
aversions = {};
for i in range(256):
	aversions[i] = "version %d" % i;
aversions[0] = 'Bitcoin';
aversions[52] = 'Namecoin';
aversions[111] = 'Testnet';

def iais(a):
	return 's' if a>=2 else ''

def determine_db_dir():
	import os
	import os.path
	import platform
	if platform.system() == "Darwin":
		return os.path.expanduser("~/Library/Application Support/Bitcoin/")
	elif platform.system() == "Windows":
		return os.path.join(os.environ['APPDATA'], "Bitcoin")
	return os.path.expanduser("~/.bitcoin")

# secp256k1

_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

class CurveFp( object ):
	def __init__( self, p, a, b ):
		self.__p = p
		self.__a = a
		self.__b = b

	def p( self ):
		return self.__p

	def a( self ):
		return self.__a

	def b( self ):
		return self.__b

	def contains_point( self, x, y ):
		return ( y * y - ( x * x * x + self.__a * x + self.__b ) ) % self.__p == 0

class Point( object ):
	def __init__( self, curve, x, y, order = None ):
		self.__curve = curve
		self.__x = x
		self.__y = y
		self.__order = order
		if self.__curve: assert self.__curve.contains_point( x, y )
		if order: assert self * order == INFINITY
 
	def __add__( self, other ):
		if other == INFINITY: return self
		if self == INFINITY: return other
		assert self.__curve == other.__curve
		if self.__x == other.__x:
			if ( self.__y + other.__y ) % self.__curve.p() == 0:
				return INFINITY
			else:
				return self.double()

		p = self.__curve.p()
		l = ( ( other.__y - self.__y ) * \
					inverse_mod( other.__x - self.__x, p ) ) % p
		x3 = ( l * l - self.__x - other.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def __mul__( self, other ):
		def leftmost_bit( x ):
			assert x > 0
			result = 1L
			while result <= x: result = 2 * result
			return result / 2

		e = other
		if self.__order: e = e % self.__order
		if e == 0: return INFINITY
		if self == INFINITY: return INFINITY
		assert e > 0
		e3 = 3 * e
		negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
		i = leftmost_bit( e3 ) / 2
		result = self
		while i > 1:
			result = result.double()
			if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
			if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
			i = i / 2
		return result

	def __rmul__( self, other ):
		return self * other

	def __str__( self ):
		if self == INFINITY: return "infinity"
		return "(%d,%d)" % ( self.__x, self.__y )

	def double( self ):
		if self == INFINITY:
			return INFINITY

		p = self.__curve.p()
		a = self.__curve.a()
		l = ( ( 3 * self.__x * self.__x + a ) * \
					inverse_mod( 2 * self.__y, p ) ) % p
		x3 = ( l * l - 2 * self.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def x( self ):
		return self.__x

	def y( self ):
		return self.__y

	def curve( self ):
		return self.__curve
	
	def order( self ):
		return self.__order
		
INFINITY = Point( None, None, None )

def inverse_mod( a, m ):
	if a < 0 or m <= a: a = a % m
	c, d = a, m
	uc, vc, ud, vd = 1, 0, 0, 1
	while c != 0:
		q, c, d = divmod( d, c ) + ( c, )
		uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
	assert d == 1
	if ud > 0: return ud
	else: return ud + m

class Signature( object ):
	def __init__( self, r, s ):
		self.r = r
		self.s = s
		
class Public_key( object ):
	def __init__( self, generator, point ):
		self.curve = generator.curve()
		self.generator = generator
		self.point = point
		n = generator.order()
		if not n:
			raise RuntimeError, "Generator point must have order."
		if not n * point == INFINITY:
			raise RuntimeError, "Generator point order is bad."
		if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
			raise RuntimeError, "Generator point has x or y out of range."

	def verifies( self, hash, signature ):
		G = self.generator
		n = G.order()
		r = signature.r
		s = signature.s
		if r < 1 or r > n-1: return False
		if s < 1 or s > n-1: return False
		c = inverse_mod( s, n )
		u1 = ( hash * c ) % n
		u2 = ( r * c ) % n
		xy = u1 * G + u2 * self.point
		v = xy.x() % n
		return v == r

class Private_key( object ):
	def __init__( self, public_key, secret_multiplier ):
		self.public_key = public_key
		self.secret_multiplier = secret_multiplier

	def der( self ):
		hex_der_key = '06052b8104000a30740201010420' + \
			'%064x' % self.secret_multiplier + \
			'a00706052b8104000aa14403420004' + \
			'%064x' % self.public_key.point.x() + \
			'%064x' % self.public_key.point.y()
		return hex_der_key.decode('hex')

	def sign( self, hash, random_k ):
		G = self.public_key.generator
		n = G.order()
		k = random_k % n
		p1 = k * G
		r = p1.x()
		if r == 0: raise RuntimeError, "amazingly unlucky random number r"
		s = ( inverse_mod( k, n ) * \
					( hash + ( self.secret_multiplier * r ) % n ) ) % n
		if s == 0: raise RuntimeError, "amazingly unlucky random number s"
		return Signature( r, s )

class EC_KEY(object):
	def __init__( self, secret ):
		curve = CurveFp( _p, _a, _b )
		generator = Point( curve, _Gx, _Gy, _r )
		self.pubkey = Public_key( generator, generator * secret )
		self.privkey = Private_key( self.pubkey, secret )
		self.secret = secret

def i2d_ECPrivateKey(pkey):
	# private keys are 279 bytes long (see crypto/ec/cec_asn1.c)
	# ASN1_SIMPLE(EC_PRIVATEKEY, version, LONG),
	# ASN1_SIMPLE(EC_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
	# ASN1_EXP_OPT(EC_PRIVATEKEY, parameters, ECPKPARAMETERS, 0),
	# ASN1_EXP_OPT(EC_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
	hex_i2d_key = '308201130201010420' + \
		'%064x' % pkey.secret + \
		'a081a53081a2020101302c06072a8648ce3d0101022100' + \
		'%064x' % _p + \
		'3006040100040107044104' + \
		'%064x' % _Gx + \
		'%064x' % _Gy + \
		'022100' + \
		'%064x' % _r + \
		'020101a14403420004' + \
		'%064x' % pkey.pubkey.point.x() + \
		'%064x' % pkey.pubkey.point.y()
	return hex_i2d_key.decode('hex')

def i2o_ECPublicKey(pkey):
	# public keys are 65 bytes long (520 bits)
	# 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
	hex_i2o_key = '04' + \
		'%064x' % pkey.pubkey.point.x() + \
		'%064x' % pkey.pubkey.point.y()
	return hex_i2o_key.decode('hex')

# hashes

def hash_160(public_key):
 	md = hashlib.new('ripemd160')
	md.update(hashlib.sha256(public_key).digest())
	return md.digest()

def public_key_to_bc_address(public_key):
	h160 = hash_160(public_key)
	return hash_160_to_bc_address(h160)

def hash_160_to_bc_address(h160):
	vh160 = chr(addrtype) + h160
	h = Hash(vh160)
	addr = vh160 + h[0:4]
	return b58encode(addr)

def bc_address_to_hash_160(addr):
	bytes = b58decode(addr, 25)
	return bytes[1:21]

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
	""" encode v, which is a string of bytes, to base58.		
	"""

	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += (256**i) * ord(c)

	result = ''
	while long_value >= __b58base:
		div, mod = divmod(long_value, __b58base)
		result = __b58chars[mod] + result
		long_value = div
	result = __b58chars[long_value] + result

	# Bitcoin does a little leading-zero-compression:
	# leading 0-bytes in the input become leading-1s
	nPad = 0
	for c in v:
		if c == '\0': nPad += 1
		else: break

	return (__b58chars[0]*nPad) + result

def b58decode(v, length):
	""" decode v into a string of len bytes
	"""
	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += __b58chars.find(c) * (__b58base**i)

	result = ''
	while long_value >= 256:
		div, mod = divmod(long_value, 256)
		result = chr(mod) + result
		long_value = div
	result = chr(long_value) + result

	nPad = 0
	for c in v:
		if c == __b58chars[0]: nPad += 1
		else: break

	result = chr(0)*nPad + result
	if length is not None and len(result) != length:
		return None

	return result

def long_hex(bytes):
	return bytes.encode('hex_codec')

def Hash(data):
	return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def EncodeBase58Check(vchIn):
	hash = Hash(vchIn)
	return b58encode(vchIn + hash[0:4])

def DecodeBase58Check(psz):
	vchRet = b58decode(psz, None)
	key = vchRet[0:-4]
	csum = vchRet[-4:]
	hash = Hash(key)
	cs32 = hash[0:4]
	if cs32 != csum:
		return None
	else:
		return key

def str_to_long(b):
	res = 0
	pos = 1
	for a in reversed(b):
		res += ord(a) * pos
		pos *= 256
	return res

def PrivKeyToSecret(privkey):
	return privkey[9:9+32]

def SecretToASecret(secret):
	vchIn = chr(addrtype+128) + secret
	return EncodeBase58Check(vchIn)

def ASecretToSecret(key):
	vch = DecodeBase58Check(key)
	if vch and vch[0] == chr(addrtype+128):
		return vch[1:]
	else:
		return False

def regenerate_key(sec):
	b = ASecretToSecret(sec)
	if not b:
		return False
	secret = str_to_long(b)	
	return EC_KEY(secret)

def GetPubKey(pkey):
	return i2o_ECPublicKey(pkey)

def GetPrivKey(pkey):
	return i2d_ECPrivateKey(pkey)

def GetSecret(pkey):
	return ('%064x' % pkey.secret).decode('hex')

# parser

def create_env(db_dir):
	db_env = DBEnv(0)
	r = db_env.open(db_dir, (DB_CREATE|DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|DB_INIT_TXN|DB_THREAD|DB_RECOVER))
	return db_env

def parse_CAddress(vds):
	d = {'ip':'0.0.0.0','port':0,'nTime': 0}
	try:
		d['nVersion'] = vds.read_int32()
		d['nTime'] = vds.read_uint32()
		d['nServices'] = vds.read_uint64()
		d['pchReserved'] = vds.read_bytes(12)
		d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
		d['port'] = vds.read_uint16()
	except:
		pass
	return d

def deserialize_CAddress(d):
	return d['ip']+":"+str(d['port'])

def parse_BlockLocator(vds):
	d = { 'hashes' : [] }
	nHashes = vds.read_compact_size()
	for i in xrange(nHashes):
		d['hashes'].append(vds.read_bytes(32))
		return d

def deserialize_BlockLocator(d):
  result = "Block Locator top: "+d['hashes'][0][::-1].encode('hex_codec')
  return result

def parse_setting(setting, vds):
	if setting[0] == "f":	# flag (boolean) settings
		return str(vds.read_boolean())
	elif setting[0:4] == "addr": # CAddress
		d = parse_CAddress(vds)
		return deserialize_CAddress(d)
	elif setting == "nTransactionFee":
		return vds.read_int64()
	elif setting == "nLimitProcessors":
		return vds.read_int32()
	return 'unknown setting'

class SerializationError(Exception):
	""" Thrown when there's a problem deserializing or serializing """

class BCDataStream(object):
	def __init__(self):
		self.input = None
		self.read_cursor = 0

	def clear(self):
		self.input = None
		self.read_cursor = 0

	def write(self, bytes):	# Initialize with string of bytes
		if self.input is None:
			self.input = bytes
		else:
			self.input += bytes

	def map_file(self, file, start):	# Initialize with bytes from file
		self.input = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
		self.read_cursor = start
	def seek_file(self, position):
		self.read_cursor = position
	def close_file(self):
		self.input.close()

	def read_string(self):
		# Strings are encoded depending on length:
		# 0 to 252 :	1-byte-length followed by bytes (if any)
		# 253 to 65,535 : byte'253' 2-byte-length followed by bytes
		# 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
		# ... and the Bitcoin client is coded to understand:
		# greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
		# ... but I don't think it actually handles any strings that big.
		if self.input is None:
			raise SerializationError("call write(bytes) before trying to deserialize")

		try:
			length = self.read_compact_size()
		except IndexError:
			raise SerializationError("attempt to read past end of buffer")

		return self.read_bytes(length)

	def write_string(self, string):
		# Length-encoded as with read-string
		self.write_compact_size(len(string))
		self.write(string)

	def read_bytes(self, length):
		try:
			result = self.input[self.read_cursor:self.read_cursor+length]
			self.read_cursor += length
			return result
		except IndexError:
			raise SerializationError("attempt to read past end of buffer")

		return ''

	def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
	def read_int16(self): return self._read_num('<h')
	def read_uint16(self): return self._read_num('<H')
	def read_int32(self): return self._read_num('<i')
	def read_uint32(self): return self._read_num('<I')
	def read_int64(self): return self._read_num('<q')
	def read_uint64(self): return self._read_num('<Q')

	def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
	def write_int16(self, val): return self._write_num('<h', val)
	def write_uint16(self, val): return self._write_num('<H', val)
	def write_int32(self, val): return self._write_num('<i', val)
	def write_uint32(self, val): return self._write_num('<I', val)
	def write_int64(self, val): return self._write_num('<q', val)
	def write_uint64(self, val): return self._write_num('<Q', val)

	def read_compact_size(self):
		size = ord(self.input[self.read_cursor])
		self.read_cursor += 1
		if size == 253:
			size = self._read_num('<H')
		elif size == 254:
			size = self._read_num('<I')
		elif size == 255:
			size = self._read_num('<Q')
		return size

	def write_compact_size(self, size):
		if size < 0:
			raise SerializationError("attempt to write size < 0")
		elif size < 253:
			 self.write(chr(size))
		elif size < 2**16:
			self.write('\xfd')
			self._write_num('<H', size)
		elif size < 2**32:
			self.write('\xfe')
			self._write_num('<I', size)
		elif size < 2**64:
			self.write('\xff')
			self._write_num('<Q', size)

	def _read_num(self, format):
		(i,) = struct.unpack_from(format, self.input, self.read_cursor)
		self.read_cursor += struct.calcsize(format)
		return i

	def _write_num(self, format, num):
		s = struct.pack(format, num)
		self.write(s)

def open_wallet(db_env, walletfile, writable=False):
	db = DB(db_env)
	flags = DB_THREAD | (DB_CREATE if writable else DB_RDONLY)
	try:
		r = db.open(walletfile, "main", DB_BTREE, flags)
	except DBError:
		r = True

	if r is not None:
		logging.error("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")
		sys.exit(1)
	
	return db

def inversetxid(txid):
	if len(txid) is not 64:
		print("Bad txid")
		exit(0)
	new_txid = ""
	for i in range(32):
		new_txid += txid[62-2*i];
		new_txid += txid[62-2*i+1];
	return new_txid

def parse_wallet(db, item_callback):
	kds = BCDataStream()
	vds = BCDataStream()


	def parse_TxIn(vds):
		d = {}
		d['prevout_hash'] = vds.read_bytes(32).encode('hex')
		d['prevout_n'] = vds.read_uint32()
		d['scriptSig'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
		d['sequence'] = vds.read_uint32()
		return d


	def parse_TxOut(vds):
		d = {}
		d['value'] = vds.read_int64()/1e8
		d['scriptPubKey'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
		return d

	
	for (key, value) in db.items():
		d = { }

		kds.clear(); kds.write(key)
		vds.clear(); vds.write(value)

		type = kds.read_string()

		d["__key__"] = key
		d["__value__"] = value
		d["__type__"] = type

		try:
			if type == "tx":
				d["tx_id"] = inversetxid(kds.read_bytes(32).encode('hex_codec'))
				start = vds.read_cursor
				d['version'] = vds.read_int32()
				n_vin = vds.read_compact_size()
				d['txIn'] = []
				for i in xrange(n_vin):
					d['txIn'].append(parse_TxIn(vds))
				n_vout = vds.read_compact_size()
				d['txOut'] = []
				for i in xrange(n_vout):
					d['txOut'].append(parse_TxOut(vds))
				d['lockTime'] = vds.read_uint32()
				d['tx'] = vds.input[start:vds.read_cursor]
			elif type == "name":
				d['hash'] = kds.read_string()
				d['name'] = vds.read_string()
			elif type == "version":
				d['version'] = vds.read_uint32()
			elif type == "setting":
				d['setting'] = kds.read_string()
				d['value'] = parse_setting(d['setting'], vds)
			elif type == "key":
				d['public_key'] = kds.read_bytes(kds.read_compact_size())
				d['private_key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "wkey":
				d['public_key'] = kds.read_bytes(kds.read_compact_size())
				d['private_key'] = vds.read_bytes(vds.read_compact_size())
				d['created'] = vds.read_int64()
				d['expires'] = vds.read_int64()
				d['comment'] = vds.read_string()
			elif type == "defaultkey":
				d['key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "pool":
				d['n'] = kds.read_int64()
				d['nVersion'] = vds.read_int32()
				d['nTime'] = vds.read_int64()
				d['public_key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "acc":
				d['account'] = kds.read_string()
				d['nVersion'] = vds.read_int32()
				d['public_key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "acentry":
				d['account'] = kds.read_string()
				d['n'] = kds.read_uint64()
				d['nVersion'] = vds.read_int32()
				d['nCreditDebit'] = vds.read_int64()
				d['nTime'] = vds.read_int64()
				d['otherAccount'] = vds.read_string()
				d['comment'] = vds.read_string()
			elif type == "bestblock":
				d['nVersion'] = vds.read_int32()
				d.update(parse_BlockLocator(vds))
			
			item_callback(type, d)

		except Exception, e:
			traceback.print_exc()
			print("ERROR parsing wallet.dat, type %s" % type)
			print("key data in hex: %s"%key.encode('hex_codec'))
			print("value data in hex: %s"%value.encode('hex_codec'))
			sys.exit(1)
	
def delete_from_wallet(db_env, walletfile, typedel, keydel):
	db = open_wallet(db_env, walletfile, True)
	kds = BCDataStream()
	vds = BCDataStream()

	deleted_items = 0
	for (key, value) in db.items():
		kds.clear(); kds.write(key)
		vds.clear(); vds.write(value)
		type = kds.read_string()

		if typedel == "tx":
			if type == "tx":
				if keydel == inversetxid(kds.read_bytes(32).encode('hex_codec')):
					db.delete(key)
					deleted_items+=1
		elif typedel == "key":
			if type == "key":
				if keydel == public_key_to_bc_address(kds.read_bytes(kds.read_compact_size())):
					db.delete(key)
					deleted_items+=1
			elif type == "pool":
				vds.read_int32()
				vds.read_int64()
				if keydel == public_key_to_bc_address(vds.read_bytes(vds.read_compact_size())):
					db.delete(key)
					deleted_items+=1
			elif type == "name":
				if keydel == kds.read_string():
					db.delete(key)
					deleted_items+=1
				

	db.close()
	return deleted_items

def update_wallet(db, type, data):
	"""Write a single item to the wallet.
	db must be open with writable=True.
	type and data are the type code and data dictionary as parse_wallet would
	give to item_callback.
	data's __key__, __value__ and __type__ are ignored; only the primary data
	fields are used.
	"""
	d = data
	kds = BCDataStream()
	vds = BCDataStream()

	# Write the type code to the key
	kds.write_string(type)
	vds.write("")						 # Ensure there is something

	try:
		if type == "tx":
			raise NotImplementedError("Writing items of type 'tx'")
			kds.write(d['tx_id'])
		elif type == "name":
			kds.write_string(d['hash'])
			vds.write_string(d['name'])
		elif type == "version":
			vds.write_uint32(d['version'])
		elif type == "setting":
			raise NotImplementedError("Writing items of type 'setting'")
			kds.write_string(d['setting'])
			#d['value'] = parse_setting(d['setting'], vds)
		elif type == "key":
			kds.write_string(d['public_key'])
			vds.write_string(d['private_key'])
		elif type == "wkey":
			kds.write_string(d['public_key'])
			vds.write_string(d['private_key'])
			vds.write_int64(d['created'])
			vds.write_int64(d['expires'])
			vds.write_string(d['comment'])
		elif type == "defaultkey":
			vds.write_string(d['key'])
		elif type == "pool":
			kds.write_int64(d['n'])
			vds.write_int32(d['nVersion'])
			vds.write_int64(d['nTime'])
			vds.write_string(d['public_key'])
		elif type == "acc":
			kds.write_string(d['account'])
			vds.write_int32(d['nVersion'])
			vds.write_string(d['public_key'])
		elif type == "acentry":
			kds.write_string(d['account'])
			kds.write_uint64(d['n'])
			vds.write_int32(d['nVersion'])
			vds.write_int64(d['nCreditDebit'])
			vds.write_int64(d['nTime'])
			vds.write_string(d['otherAccount'])
			vds.write_string(d['comment'])
		elif type == "bestblock":
			vds.write_int32(d['nVersion'])
			vds.write_compact_size(len(d['hashes']))
			for h in d['hashes']:
				vds.write(h)
		else:
			print "Unknown key type: "+type

		# Write the key/value pair to the database
		db.put(kds.input, vds.input)

	except Exception, e:
		print("ERROR writing to wallet.dat, type %s"%type)
		print("data dictionary: %r"%data)
		traceback.print_exc()

def rewrite_wallet(db_env, walletfile, destFileName, pre_put_callback=None):
	db = open_wallet(db_env, walletfile)

	db_out = DB(db_env)
	try:
		r = db_out.open(destFileName, "main", DB_BTREE, DB_CREATE)
	except DBError:
		r = True

	if r is not None:
		logging.error("Couldn't open %s."%destFileName)
		sys.exit(1)

	def item_callback(type, d):
		if (pre_put_callback is None or pre_put_callback(type, d)):
			db_out.put(d["__key__"], d["__value__"])

	parse_wallet(db, item_callback)
	db_out.close()
	db.close()

def read_wallet(json_db, db_env, walletfile, print_wallet, print_wallet_transactions, transaction_filter, include_balance):
	db = open_wallet(db_env, walletfile)

	json_db['keys'] = []
	json_db['pool'] = []
	json_db['tx'] = []
	json_db['names'] = {}

	def item_callback(type, d):
		if type == "tx":
			json_db['tx'].append({"txid" : d['tx_id'], "txin" : d['txIn'], "txout" : d['txOut']})

		elif type == "name":
			json_db['names'][d['hash']] = d['name']

		elif type == "version":
			json_db['version'] = d['version']

		elif type == "setting":
			if not json_db.has_key('settings'): json_db['settings'] = {}
			json_db["settings"][d['setting']] = d['value']

		elif type == "defaultkey":
			json_db['defaultkey'] = public_key_to_bc_address(d['key'])

		elif type == "key":
			addr = public_key_to_bc_address(d['public_key'])
			secret = PrivKeyToSecret(d['private_key'])
			hexsec = secret.encode('hex')
			sec = SecretToASecret(secret)
			private_keys.append(sec)
			private_hex_keys.append(hexsec)
			json_db['keys'].append({'addr' : addr, 'sec' : sec, 'hexsec' : hexsec})

		elif type == "wkey":
			if not json_db.has_key('wkey'): json_db['wkey'] = []
			json_db['wkey']['created'] = d['created']

		elif type == "pool":
			json_db['pool'].append( {'n': d['n'], 'addr': public_key_to_bc_address(d['public_key']), 'nTime' : d['nTime'] } )

		elif type == "acc":
			json_db['acc'] = d['account']
			print("Account %s (current key: %s)"%(d['account'], public_key_to_bc_address(d['public_key'])))

		elif type == "acentry":
			json_db['acentry'] = (d['account'], d['nCreditDebit'], d['otherAccount'], time.ctime(d['nTime']), d['n'], d['comment'])

		elif type == "bestblock":
			json_db['bestblock'] = d['hashes'][0][::-1].encode('hex_codec')

		else:
			json_db[type] = 'unsupported'


	parse_wallet(db, item_callback)

	db.close()

	nkeys = len(json_db['keys'])
	i = 0
	for k in json_db['keys']:
		i+=1
		addr = k['addr']
		if include_balance is not None:
#			print("%3d/%d  %s" % (i, nkeys, k["addr"]))
			k["balance"] = balance(balance_site, k["addr"])
#			print("  %s" % (i, nkeys, k["addr"], k["balance"]))
		if addr in json_db['names'].keys():
			k["label"] = json_db['names'][addr]
		else:
			k["reserve"] = 1
	
#	del(json_db['pool'])
#	del(json_db['names'])

def importprivkey(db, sec, label, reserve, keyishex):
	if keyishex is None:
		pkey = regenerate_key(sec)
	elif len(sec) == 64:
		pkey = EC_KEY(str_to_long(sec.decode('hex')))
	else:
		print("Hexadecimal private keys must be 64 characters long")
		exit(0)

	if not pkey:
		return False

	secret = GetSecret(pkey)
	private_key = GetPrivKey(pkey)
	public_key = GetPubKey(pkey)
	addr = public_key_to_bc_address(public_key)

	print "Address: %s" % addr
	print "Privkey: %s" % SecretToASecret(secret)

	update_wallet(db, 'key', { 'public_key' : public_key, 'private_key' : private_key })
	if not reserve:
		update_wallet(db, 'name', { 'hash' : addr, 'name' : label })

	return True

def balance(site, address):
	page=urllib.urlopen("%s=%s" % (site, address))
	json_acc = json.loads(page.read().split("<end>")[0])
	if json_acc['0'] == 0:
		return "Invalid address"
	elif json_acc['0'] == 2:
		return "Never used"
	else:
		return json_acc['balance']

from optparse import OptionParser

def keyinfo(sec, keyishex):
	if keyishex is None:
		pkey = regenerate_key(sec)
	elif len(sec) == 64:
		pkey = EC_KEY(str_to_long(sec.decode('hex')))
	else:
		print("Hexadecimal private keys must be 64 characters long")
		exit(0)

	if not pkey:
		return False

	secret = GetSecret(pkey)
	private_key = GetPrivKey(pkey)
	public_key = GetPubKey(pkey)
	addr = public_key_to_bc_address(public_key)

	print "Address (%s): %s" % ( aversions[addrtype], addr )
	print "Privkey (%s): %s" % ( aversions[addrtype], SecretToASecret(secret) )
	print "Hexprivkey: %s" % secret.encode('hex')

	return True

class WIRoot(resource.Resource):

    def render_GET(self, request):
			header = '<h1>Pywallet Web Interface</h1><h3>CLOSE BITCOIN BEFORE USE!</h3><br /><br />'

			DWForm = '<h3>Dump your wallet:</h3><form style="margin-left:15px;" action="DumpWallet" method=get>\
					Wallet Directory: <input type=text name="dir" id="dwf-dir" size=40 value="' + determine_db_dir() + '" /><br />\
					Wallet Filename: <input type=text name="name" id="dwf-name" value="wallet.dat" /><br />\
					<input type=submit value="Dump wallet" onClick="document.getElementById(\'DWDiv\').style.display=\'block\';document.getElementById(\'dwf-close\').style.display=\'inline\';ajaxDW();return false;" />\
					<input type=button value="Close" onClick="document.getElementById(\'DWDiv\').style.display=\'none\';document.getElementById(\'dwf-close\').style.display=\'none\';" id="dwf-close" style="display:none;" />\
					<div id="DWDiv" style="display:none;margin:10px 3% 10px;padding:10px;overflow:auto;width:50%;max-height:600px;background-color:#fff8dd;"></div>\
				</form><br />'

			InfoForm = '<h3>Get some info about one key:</h3><form style="margin-left:15px;" action="Info" method=get>\
					Key: <input type=text name="key" id="if-key" size=65 /><br />\
					<span style="border: 0 dashed;border-bottom-width:1px;" title="0 for Bitcoin, 52 for Namecoin, 111 for testnets">Version</span>: <input type=text name="vers" value=0 id="if-vers" size=1 /><br />\
					Format:<br />\
					<input type="radio" name="format" value="reg" CHECKED> Regular, base 58<br>\
					<input type="radio" name="format" value="hex" id="if-hex"> Hexadecimal, 64 characters long<br>\
					<input type=submit value="Get info" onClick="document.getElementById(\'InfoDiv\').style.display=\'block\';document.getElementById(\'if-close\').style.display=\'inline\';ajaxInfo();return false;" />\
					<input type=button value="Close" onClick="document.getElementById(\'InfoDiv\').style.display=\'none\';document.getElementById(\'if-close\').style.display=\'none\';" id="if-close" style="display:none;" />\
					<div id="InfoDiv" style="display:none;margin:10px 3% 10px;padding:10px;overflow:auto;width:50%;max-height:300px;background-color:#fff8dd;"></div>\
				</form><br />'

			ImportForm = '<h3>Import a key in your wallet:</h3><form style="margin-left:15px;" action="Import" method=get>\
					Wallet Directory: <input type=text name="dir" id="impf-dir" size=40 value="' + determine_db_dir() + '" /><br />\
					Wallet Filename: <input type=text name="name" id="impf-name" value="wallet.dat" /><br />\
					Key: <input type=text name="key" id="impf-key" size=65 /><br />\
					Label: <input type=text name="label" id="impf-label" /><br />\
					<input type="checkbox" name="reserve" value="true" id="impf-reserve" onClick="document.getElementById(\'impf-label\').disabled=document.getElementById(\'impf-reserve\').checked" /> Reserve<br />\
					<span style="border: 0 dashed;border-bottom-width:1px;" title="0 for Bitcoin, 52 for Namecoin, 111 for testnets">Version</span>: <input type=text name="vers" value=0 id="impf-vers" size=1 /><br />\
					Format:<br />\
					<input type="radio" name="format" value="reg" CHECKED> Regular, base 58<br>\
					<input type="radio" name="format" value="hex"  id="impf-hex" > Hexadecimal, 64 characters long<br>\
					<input type=submit value="Import key" onClick="document.getElementById(\'ImportDiv\').style.display=\'block\';document.getElementById(\'impf-close\').style.display=\'inline\';ajaxImport();return false;" />\
					<input type=button value="Close" onClick="document.getElementById(\'ImportDiv\').style.display=\'none\';document.getElementById(\'impf-close\').style.display=\'none\';" id="impf-close" style="display:none;" />\
					<div id="ImportDiv" style="display:none;margin:10px 3% 10px;padding:10px;overflow:auto;width:50%;max-height:300px;background-color:#fff8dd;"></div>\
				</form><br />'

			DeleteForm = '<h3>Delete a key from your wallet:</h3><form style="margin-left:15px;" action="Delete" method=get>\
					Wallet Directory: <input type=text name="dir" id="d-dir" size=40 value="' + determine_db_dir() + '" /><br />\
					Wallet Filename: <input type=text name="name" id="d-name" value="wallet.dat" /><br />\
					Key: <input type=text name="key" id="d-key" size=65 /><br />\
					Type:<br />\
					<input type="radio" name="d-type" value="tx" CHECKED> Transaction<br>\
					<input type="radio" name="d-type" value="key"> Bitcoin address<br>\
					<input type=submit value="Delete" onClick="document.getElementById(\'DeleteDiv\').style.display=\'block\';document.getElementById(\'d-close\').style.display=\'inline\';ajaxDelete();return false;" />\
					<input type=button value="Close" onClick="document.getElementById(\'DeleteDiv\').style.display=\'none\';document.getElementById(\'d-close\').style.display=\'none\';" id="d-close" style="display:none;" />\
					<div id="DeleteDiv" style="display:none;margin:10px 3% 10px;padding:10px;overflow:auto;width:50%;max-height:300px;background-color:#fff8dd;"></div>\
				</form><br />'

			BalanceForm = '<h3>Print the balance of a Bitcoin address:</h3><form style="margin-left:15px;" action="Balance" method=get>\
					Key: <input type=text name="key" id="bf-key" size=35 /><br />\
					<input type=submit value="Get balance" onClick="ajaxBalance();return false;" /><br /><br />\
					<div id="BalanceDiv"></div>\
				</form><br /><br /><br /><br />'

			Misc = ''

			Javascript = '<script language="javascript" type="text/javascript">\
				function get_radio_value(radioform){\
					var rad_val;\
					for (var i=0; i < radioform.length; i++){\
						if (radioform[i].checked){\
							rad_val = radioform[i].value;\
						}\
					}\
					return rad_val;\
				}\
				function ajaxDW(){\
					var ajaxRequest;\
					try{\
						ajaxRequest = new XMLHttpRequest();\
					} catch (e){\
						try{\
							ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");\
						} catch (e) {\
							try{\
								ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");\
							} catch (e){\
								alert("Your browser broke!");\
								return false;\
							}\
						}\
					}\
					ajaxRequest.onreadystatechange = function(){\
						if(ajaxRequest.readyState == 4){\
							document.getElementById("DWDiv").innerHTML = ajaxRequest.responseText;\
						}\
					};\
					var queryString = "/DumpWallet?dir="+document.getElementById("dwf-dir").value+"&name="+document.getElementById("dwf-name").value;\
					ajaxRequest.open("GET", queryString, true);\
					document.getElementById("DWDiv").innerHTML = "Loading...";\
					ajaxRequest.send(null);\
 				}\
				function ajaxInfo(){\
					var ajaxRequest;\
					try{\
						ajaxRequest = new XMLHttpRequest();\
					} catch (e){\
						try{\
							ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");\
						} catch (e) {\
							try{\
								ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");\
							} catch (e){\
								alert("Your browser broke!");\
								return false;\
							}\
						}\
					}\
					ajaxRequest.onreadystatechange = function(){\
						if(ajaxRequest.readyState == 4){\
							document.getElementById("InfoDiv").innerHTML = ajaxRequest.responseText;\
						}\
					};\
					var queryString = "/Info?key="+document.getElementById("if-key").value+"&vers="+document.getElementById("if-vers").value+"&format="+(document.getElementById("if-hex").checked?"hex":"reg");\
					ajaxRequest.open("GET", queryString, true);\
					document.getElementById("InfoDiv").innerHTML = "Loading...";\
					ajaxRequest.send(null);\
 				}\
				function ajaxImport(){\
					var ajaxRequest;\
					try{\
						ajaxRequest = new XMLHttpRequest();\
					} catch (e){\
						try{\
							ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");\
						} catch (e) {\
							try{\
								ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");\
							} catch (e){\
								alert("Your browser broke!");\
								return false;\
							}\
						}\
					}\
					ajaxRequest.onreadystatechange = function(){\
						if(ajaxRequest.readyState == 4){\
							document.getElementById("ImportDiv").innerHTML = ajaxRequest.responseText;\
						}\
					};\
					var queryString = "/Import?dir="+document.getElementById("impf-dir").value+"&name="+document.getElementById("impf-name").value+"&key="+document.getElementById("impf-key").value+"&label="+document.getElementById("impf-label").value+"&vers="+document.getElementById("impf-vers").value+"&format="+(document.getElementById("impf-hex").checked?"hex":"reg")+(document.getElementById("impf-reserve").checked?"&reserve=1":"");\
					ajaxRequest.open("GET", queryString, true);\
					document.getElementById("ImportDiv").innerHTML = "Loading...";\
					ajaxRequest.send(null);\
 				}\
				function ajaxBalance(){\
					var ajaxRequest;\
					try{\
						ajaxRequest = new XMLHttpRequest();\
					} catch (e){\
						try{\
							ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");\
						} catch (e) {\
							try{\
								ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");\
							} catch (e){\
								alert("Your browser broke!");\
								return false;\
							}\
						}\
					}\
					ajaxRequest.onreadystatechange = function(){\
						if(ajaxRequest.readyState == 4){\
							document.getElementById("BalanceDiv").innerHTML = "Balance of " + document.getElementById("bf-key").value + ": " + ajaxRequest.responseText;\
						}\
					};\
					var queryString = "/Balance?key="+document.getElementById("bf-key").value;\
					ajaxRequest.open("GET", queryString, true);\
					document.getElementById("BalanceDiv").innerHTML = "Loading...";\
					ajaxRequest.send(null);\
 				}\
				function ajaxDelete(){\
					var ajaxRequest;\
					try{\
						ajaxRequest = new XMLHttpRequest();\
					} catch (e){\
						try{\
							ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");\
						} catch (e) {\
							try{\
								ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");\
							} catch (e){\
								alert("Your browser broke!");\
								return false;\
							}\
						}\
					}\
					ajaxRequest.onreadystatechange = function(){\
						if(ajaxRequest.readyState == 4){\
							document.getElementById("DeleteDiv").innerHTML = ajaxRequest.responseText;\
						}\
					};\
					var queryString = "/Delete?dir="+document.getElementById("d-dir").value+"&name="+document.getElementById("d-name").value+"&keydel="+document.getElementById("d-key").value+"&typedel="+get_radio_value(document.getElementsByName("d-type"));\n\
					ajaxRequest.open("GET", queryString, true);\n\
					document.getElementById("DeleteDiv").innerHTML = "Loading...";\
					ajaxRequest.send(null);\
 				}\
				</script>'

			page = '<html><head><title>Pywallet Web Interface</title></head><body>' + header + Javascript + DWForm + InfoForm + ImportForm + DeleteForm + BalanceForm + Misc + '</body></html>'
			return page

    def getChild(self, name, request):
        if name == '':
            return self
        else:
            if name in VIEWS.keys():
                return resource.Resource.getChild(self, name, request)
            else:
                return WI404()

class WIDumpWallet(resource.Resource):

    def render_GET(self, request):
        try:
				wdir=request.args['dir'][0]
				wname=request.args['name'][0]
				log.msg('Wallet Dir: %s' %(wdir))
				log.msg('Wallet Name: %s' %(wname))

				if not os.path.isfile(wdir+"/"+wname):
					return '%s/%s doesn\'t exist'%(wdir, wname)

				read_wallet(json_db, create_env(wdir), wname, True, True, "", None)
				return 'Wallet: %s/%s<br />Dump:<pre>%s</pre>'%(wdir, wname, json.dumps(json_db, sort_keys=True, indent=4))
        except:
            log.err()
            return 'Error in dump page'

        def render_POST(self, request):
            return self.render_GET(request)

class WIBalance(resource.Resource):

    def render_GET(self, request):
        try:
				return "%s"%str(balance(balance_site, request.args['key'][0]).encode('utf-8'))
        except:
            log.err()
            return 'Error in balance page'

        def render_POST(self, request):
            return self.render_GET(request)

class WIDelete(resource.Resource):

    def render_GET(self, request):
        try:
				wdir=request.args['dir'][0]
				wname=request.args['name'][0]
				keydel=request.args['keydel'][0]
				typedel=request.args['typedel'][0]
				db_env = create_env(wdir)

				if not os.path.isfile(wdir+"/"+wname):
					return '%s/%s doesn\'t exist'%(wdir, wname)

				deleted_items = delete_from_wallet(db_env, wname, typedel, keydel)

				return "%s:%s has been successfully deleted from %s/%s, resulting in %d deleted item%s"%(typedel, keydel, wdir, wname, deleted_items, iais(deleted_items))

        except:
            log.err()
            return 'Error in delete page'

        def render_POST(self, request):
            return self.render_GET(request)

class WIInfo(resource.Resource):

    def render_GET(self, request):
        global addrtype
        try:
				sec = request.args['key'][0]
				format = request.args['format'][0]
				addrtype = int(request.args['vers'][0])
				
				if format in 'reg':
					pkey = regenerate_key(sec)
				elif len(sec) == 64:
					pkey = EC_KEY(str_to_long(sec.decode('hex')))
				else:
					return "Hexadecimal private keys must be 64 characters long"

				if not pkey:
					return "Bad private key"

				secret = GetSecret(pkey)
				private_key = GetPrivKey(pkey)
				public_key = GetPubKey(pkey)
				addr = public_key_to_bc_address(public_key)

				return "Address (%s): %s<br />Privkey (%s): %s<br />Hexprivkey: %s" % ( aversions[addrtype], addr, aversions[addrtype], SecretToASecret(secret), secret.encode('hex') )

        except:
            log.err()
            return 'Error in info page'

        def render_POST(self, request):
            return self.render_GET(request)


class WIImport(resource.Resource):

    def render_GET(self, request):
        global addrtype
        try:
				sec = request.args['key'][0]
				format = request.args['format'][0]
				addrtype = int(request.args['vers'][0])
				wdir=request.args['dir'][0]
				wname=request.args['name'][0]
				reserve=request.args.has_key('reserve')
				label=request.args['label'][0]
				
				if format in 'reg':
					pkey = regenerate_key(sec)
				elif len(sec) == 64:
					pkey = EC_KEY(str_to_long(sec.decode('hex')))
				else:
					return "Hexadecimal private keys must be 64 characters long"

				if not pkey:
					return "Bad private key"

				if not os.path.isfile(wdir+"/"+wname):
					return '%s/%s doesn\'t exist'%(wdir, wname)


				secret = GetSecret(pkey)
				private_key = GetPrivKey(pkey)
				public_key = GetPubKey(pkey)
				addr = public_key_to_bc_address(public_key)

				db_env = create_env(wdir)
				read_wallet(json_db, db_env, wname, True, True, "", None)
				db = open_wallet(db_env, wname, writable=True)

				if (format in 'reg' and sec in private_keys) or (format not in 'reg' and sec in private_hex_keys):
					return "Already exists"

				update_wallet(db, 'key', { 'public_key' : public_key, 'private_key' : private_key })
				if not reserve:
					update_wallet(db, 'name', { 'hash' : addr, 'name' : label })
	
				db.close()

				return "<pre>Address: %s\nPrivkey: %s\nHexkey: %s\nKey imported in %s/%s<pre>" % (addr, SecretToASecret(secret), secret.encode('hex'), wdir, wname)

        except:
            log.err()
            return 'Error in import page'

        def render_POST(self, request):
            return self.render_GET(request)

class WI404(resource.Resource):

    def render_GET(self, request):
        return 'Page Not Found'


if __name__ == '__main__':

	parser = OptionParser(usage="%prog [options]", version="%prog 1.1")

	parser.add_option("--dumpwallet", dest="dump", action="store_true",
		help="dump wallet in json format")

#	parser.add_option("--dumpwithbalance", dest="dumpbalance", action="store_true",
#		help="includes balance of each address in the json dump, can take a *LONG* time and might experience timeouts or bans")

	parser.add_option("--importprivkey", dest="key", 
		help="import private key from vanitygen")

	parser.add_option("--importhex", dest="keyishex", action="store_true", 
		help="KEY is in hexadecimal format")

	parser.add_option("--datadir", dest="datadir", 
		help="wallet directory (defaults to bitcoin default)")

	parser.add_option("--wallet", dest="walletfile", 
		help="wallet filename (defaults to wallet.dat)",
		default="wallet.dat")

	parser.add_option("--label", dest="label", 
		help="label shown in the adress book (defaults to '')",
		default="")

	parser.add_option("--testnet", dest="testnet", action="store_true",
		help="use testnet subdirectory and address type")

	parser.add_option("--namecoin", dest="namecoin", action="store_true",
		help="use namecoin address type")

	parser.add_option("--otherversion", dest="otherversion",
		help="use other network address type, whose version is OTHERVERSION")

	parser.add_option("--info", dest="keyinfo", action="store_true",
		help="display pubkey, privkey (both depending on the network) and hexkey")

	parser.add_option("--reserve", dest="reserve", action="store_true",
		help="import as a reserve key, i.e. it won't show in the adress book")

	parser.add_option("--balance", dest="key_balance",
		help="prints balance of KEY_BALANCE")

	parser.add_option("--web", dest="web", action="store_true",
		help="run pywallet web interface")

	parser.add_option("--port", dest="port",
		help="port of web interface (defaults to 8989)")

#	parser.add_option("--forcerun", dest="forcerun",
#		action="store_true",
#		help="run even if pywallet detects bitcoin is running")

	(options, args) = parser.parse_args()

	VIEWS = {
		 'DumpWallet': WIDumpWallet(),
		 'Import': WIImport(),
		 'Info': WIInfo(),
		 'Delete': WIDelete(),
		 'Balance': WIBalance()
	}

#	a=Popen("ps xa | grep ' bitcoin'", shell=True, bufsize=-1, stdout=PIPE).stdout
#	aread=a.read()
#	nl = aread.count("\n")
#	a.close()
#	if nl > 2:
#		print('Bitcoin seems to be running: \n"%s"'%(aread))
#		if options.forcerun is None:
#			exit(0)

	if options.web is not None:
		webport = 8989
		if options.port is not None:
			webport = int(options.port)
		root = WIRoot()
		for viewName, className in VIEWS.items():
			root.putChild(viewName, className)
		log.startLogging(sys.stdout)
		log.msg('Starting server: %s' %str(datetime.now()))
		server = server.Site(root)
		reactor.listenTCP(webport, server)
		reactor.run()
		exit(0)

	if options.key_balance is not None:
		print(balance(balance_site, options.key_balance))
		exit(0)

	if options.dump is None and options.key is None:
		print "A mandatory option is missing\n"
		parser.print_help()
		exit(0)

	if options.datadir is None:
		db_dir = determine_db_dir()
	else:
		db_dir = options.datadir

	if options.testnet:
		db_dir += "/testnet"
		addrtype = 111

	if options.namecoin or options.otherversion is not None:
		if options.datadir is None and options.keyinfo is None:
			print("You MUST provide your wallet directory")
			exit(0)
		else:
			if options.namecoin:
				addrtype = 52
			else:
				addrtype = int(options.otherversion)

	if options.keyinfo is not None:
		if not keyinfo(options.key, options.keyishex):
			print "Bad private key"
		exit(0)

	db_env = create_env(db_dir)

	read_wallet(json_db, db_env, options.walletfile, True, True, "", None)

	if options.dump:		
		print json.dumps(json_db, sort_keys=True, indent=4)
	elif options.key:
		if json_db['version'] > max_version:
			print "Version mismatch (must be <= %d)" % max_version
		elif (options.keyishex is None and options.key in private_keys) or (options.keyishex is not None and options.key in private_hex_keys):
			print "Already exists"
		else:	
			db = open_wallet(db_env, options.walletfile, writable=True)

			if importprivkey(db, options.key, options.label, options.reserve, options.keyishex):
				print "Imported successfully"
			else:
				print "Bad private key"

			db.close()


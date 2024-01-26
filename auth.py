#!/usr/bin/env python3
import os
import sys
import struct
import string
import random
import hashlib


#
# derived from:
#  https://gist.githubusercontent.com/Strangelovian/49e1ca1acd659c7dbb5fa192fc32a7bf/raw/ef9078b8c8424366faf3e00fd705fbe8539c33e0/auth.py
#

ORANGE_VENDOR_TYPE = 0x1A
ORANGE_USER_TYPE = 0x01
ORANGE_SALT_TYPE = 0x3C
ORANGE_HASH_TYPE = 0x03


def load_credentials(filepath='/etc/orange/credentials'):
	'''
	Read credentials from the given file. Empty lines and comments are ignored.
	The first username:password line found will be used.
	And do not forget to chmod o-rwx that damn file.
	'''
	with open(filepath, 'r') as filedesc:
		for line in filedesc.readlines():
			line = line.strip()
			if line and not line.startswith('#') and ':' in line:
				parts = line.split(':', 1)
				return (parts[0], parts[1])
	raise Exception('no credentials found in %s' % filepath)


def to_bytes(string, encoding='ascii'):
	'''
	Convert the given string to bytes, assuming ASCII encoding by default.
	'''
	return bytes(string, encoding)


def tlv(id, value):
	'''
	Poor man's implementation of TLV (Type, Length, Value) encoding.
	'''
	length = len(value) + 2
	if length > 253:
		raise Exception('Unable to deal with length > 253')
	return struct.pack('BB', id, length) + value


def make_salt(length=16):
	'''
	Return a binary string made of <length> random bytes.
	'''
	return os.urandom(length)


def make_ascii_salt(length=16):
	'''
	Return a string made of <length> random printable ASCII characters
	(excluding tabs).
	'''
	binary_salt = make_salt(length)
	lowest_value = ord(' ')
	highest_value = ord('~')
	interval = highest_value - lowest_value + 1
	ascii_salt = []
	for byte in binary_salt:
		ascii_salt.append(lowest_value + (byte % interval))
	return bytes(ascii_salt)


def make_orange_hash(salt, password, byte=None):
	'''
	Return byte + MD5(byte, password, salt).
	'''
	random_byte = os.urandom(1) if byte is None else byte
	md5_hasher = hashlib.md5()
	md5_hasher.update(random_byte)
	md5_hasher.update(password)
	md5_hasher.update(salt)
	return random_byte + md5_hasher.digest()


def make_orange_authentication(username, password):
	'''
	Generate and return the Orange-specific DCHP authentication value.
	'''
	salt = make_ascii_salt()
	random_char = to_bytes(random.choice(string.ascii_letters))
	hash = make_orange_hash(salt, to_bytes(password), random_char)
	# Strive to imitate what a LiveBox would generate, starting with 11 null
	# bytes:
	#   - 1 for the authentication protocol: 0 means "configuration token"
	#   - 1 for the algorithm: 0 means "none"
	#   - 1 for RDM (Replay Detection method) type: 0 means "monotonically-increasing counter"
	#   - 8 for RDM (Replay Detection method) value (here, 0, simply)
	auth = bytes(11)
	# Then, according to [1], we have a sequence of Type-Length-Value fields:
	#   - Vendor information field: type 0x1A, length 9 (1+1+7), value 00:00:05:58:01:03:41,
	#     where 0x0558 (1368) is the IANA enterprise number for Orange
	auth += tlv(ORANGE_VENDOR_TYPE, bytes([0x00, 0x00, 0x05, 0x58, 0x01, 0x03, 0x41]))
	#   - Username field: type 0x01, length 13 (1+1+11), the Orange PPP login:
	auth += tlv(ORANGE_USER_TYPE, to_bytes(username))
	#   - Salt field: type 0x3C, length 18 (1+1+16), 16-byte random salt
	auth += tlv(ORANGE_SALT_TYPE, salt)
	#   - Hash field: type 0x03, length 19 (1+1+17), 1 random byte followed by the 16-byte MD5 hash of:
	#     - that random byte
	#     - the Orange PPP password
	#     - the salt field
	auth += tlv(ORANGE_HASH_TYPE, hash)
	return auth
	# References:
	# [1] https://lafibre.info/remplacer-livebox/cacking-nouveau-systeme-de-generation-de-loption-90-dhcp/


def hex_string(auth):
    return ('0x' + ''.join(f"{byte:02x}" for byte in auth)).encode()


if __name__ == '__main__':
    auth = make_orange_authentication(*load_credentials(os.getcwd() + '/credentials'))
    #sys.stdout.buffer.write(auth)
    sys.stdout.buffer.write(hex_string(auth))
    sys.exit(0)

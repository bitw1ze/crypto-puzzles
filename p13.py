#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""
+========================+
|        ANSWER          |
+========================+

Object parsed after decryption:
  {'role': 'admin', 'email': 'baz@foobar.io', 'uid': '10'}

"""

import sys
from random import randint
from Crypto import Random
from Crypto.Cipher import AES
from helpers import chunks
from mycrypto import pkcs7_pad, aes_ecb_encrypt, aes_ecb_decrypt

p13_key = Random.new().read(AES.block_size)

def decode_profile(s):
  return dict([(k,v) for k,v in [p.split('=') for p in s.split('&')]])

def profile_for(email):
# super secure validation check
  if '&' in email or '=' in email:
    raise Exception("Not a valid email")

  return "email=%s&uid=10&role=user" % email

def encrypt_profile(pt):
  return aes_ecb_encrypt(pt, p13_key)

def decrypt_profile(ct):
  return aes_ecb_decrypt(ct, p13_key)

def encrypt_profile_for(email):
  return encrypt_profile(profile_for(email).encode('utf8'))

def admin_get():
  block_size = AES.block_size
  final_ct = b''

# get number of bytes needed to get 'role=user' on a block boundary
  _ct = encrypt_profile_for('')
  offset = 0
  for i in range(1, block_size):
    if len(encrypt_profile_for('A'*i)) != len(_ct):
      offset = i
      break
  # shift 'role=' to end of block and make our email end in .io'
  dummy = 'A'*(offset+1)+'.io'
  ct = encrypt_profile_for(dummy)
  final_ct += chunks(ct, block_size)[-2]

# first block contains email=foo@bar.co 
# make next block start with 'admin and look like last block by padding it
  dummy = 'baz@foobar'+pkcs7_pad(b'admin', block_size).decode('utf8')
  ct = encrypt_profile_for(dummy)

# put email in ciphertext in first block
  final_ct = chunks(ct, block_size)[0] + final_ct
  final_ct += chunks(ct, block_size)[1]

  return final_ct

def main():
  ciphertext = admin_get()
  print(decode_profile(decrypt_profile(ciphertext).decode('utf8')))

if __name__ == '__main__':
  sys.exit(main())

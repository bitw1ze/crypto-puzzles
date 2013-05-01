#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

from Crypto.Cipher import AES
from Crypto import Random
from mycrypto import aes_cbc_encrypt, aes_cbc_decrypt
import sys

p16_key = Random.new().read(AES.block_size)
p16_iv = Random.new().read(AES.block_size)

def encrypt_data(data):
  # I'm not sure what you mean by "quote out", but i think validating the input
  # effectively does the same thing

  if ';' in data or '=' in data:
    raise Exception("Invalid userdata")

  data = "comment1=cooking%20MCs;userdata="+data+";comment2=%20like%20a%20pound%20of%20bacon"
  from mycrypto import pkcs7_pad
  data = pkcs7_pad(data.encode('utf8'), 16)
  return AES.new(key=p16_key, IV=p16_iv, mode=AES.MODE_CBC).encrypt(data)
  #return aes_cbc_encrypt(data.encode('utf8'), p16_key, p16_iv)

def decrypt_data(data):
  pt = aes_cbc_decrypt(data, p16_key, p16_iv)
  print(pt)
  pairs = decode(pt.decode('utf8', 'ignore'))
  print(pairs)
  return 'admin' in pairs.keys() and pairs['admin'] == 'true'

def decode(s):
  return dict([(k,v) for k,v in [p.split('=') for p in s.split(';')]])

def admin_get():
  ct = encrypt_data('fooba|admin:true')
  pos = 16 + 6
  chosen_ct = ct[0:pos] + b'A' + ct[pos+1:]
  pt = decrypt_data(chosen_ct)
  #print(pt)

def main():
  admin_get()

if __name__ == '__main__':
  sys.exit(main())

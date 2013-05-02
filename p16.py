#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""
+========================+
|        ANSWER          |
+========================+

Unauthenticated CBC mode is vulnerable to chosen ciphertext attacks because
each block of plaintext is XORed with the previous block of ciphertext when
decrypted. See comments for admin_get() for comments on how I implemented this
attack.

"""

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
  return pt

def is_admin(ct):
  pairs = decode(decrypt_data(ct).decode('utf8', 'ignore'))
  return 'admin' in pairs.keys() and pairs['admin'] == 'true'

def decode(s):
  return dict([(k,v) for k,v in [p.split('=') for p in s.split(';')]])

def admin_get():
  """ 
  
  I add a dummy block first so as to not scramble the actual data. I then
  concat a block containing some dummy user data, 'admin', 'true', and some
  room for ';' and '='. I know the positions of where I want ';' and '=', so I
  just fiddle with the right bytes in the dummy ciphertext block until they
  generate the correct values

  I'm not sure if it's considered "cheating" for the attacker to see the
  plaintext decryption directly, so I brute-force each character and rely on
  is_admin()'s return value to know when I get the right values. It would be
  much faster if the attacker could see the decrypted values to validate each
  byte is correct one at a time -- unless I'm just missing something.

  """
  ct = encrypt_data('A'*16+"fooba|admin|true")
  pos1 = 32 + 5
  pos2 = 32 + 11
  for i in range(0, 256):
    for j in range(0, 256):
      try:
        chosen_ct = ct[:pos1] + bytes([i]) + ct[pos1+1:pos2] + bytes([j]) + ct[pos2+1:]
        if is_admin(chosen_ct):
          return chosen_ct
      except Exception as e:
        pass
    else:
      continue
    break
  else:
    raise Exception("Couldn't get admin! :(")

def main():
  print("Got admin! Proof:\n%s" % decode(decrypt_data(admin_get()).decode('utf8', 'ignore')))

if __name__ == '__main__':
  sys.exit(main())

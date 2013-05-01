#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

from Crypto import Random
from Crypto.Cipher import AES
from random import randint
from mycrypto import aes_ecb_encrypt, aes_ecb_decrypt, aes_cbc_encrypt, aes_cbc_decrypt
from p8 import detect_ecb
import sys

def encryption_oracle(pt): 
  entropy = Random.new()
  key = entropy.read(AES.block_size)
  crypt = randint(0,1)

  prefix = entropy.read(randint(5,10))
  suffix = entropy.read(randint(5,10))

  pt = prefix + pt + suffix

  if crypt == 0:
    print("Crypting in ECB mode")
    return aes_ecb_encrypt(pt, key)
  elif crypt == 1:
    print("Crypting in CBC mode")
    iv = entropy.read(AES.block_size)
    return aes_cbc_encrypt(pt, key, iv)

def main():
  print("ECB" if detect_ecb(encryption_oracle(b'A'*512)) else "CBC")
    
if __name__ == '__main__':
  sys.exit(main())

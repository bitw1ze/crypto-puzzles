from Crypto import Random
from Crypto.Cipher import AES
from random import randint
from p7 import aes_ecb_encrypt, aes_ecb_decrypt
from p10 import aes_cbc_encrypt, aes_cbc_decrypt
import sys

def aes_rand_encrypt(pt):
  key = Random.new().read(AES.block_size)
  crypt = randint(0,1)
  iv = b"\x00"*AES.block_size
  rand_prefix = Random.new().read(randint(5, 10))
  rand_suffix = Random.new().read(randint(5, 10))
  pt = rand_prefix + pt + rand_suffix

  if crypt == 0:
    return aes_ecb_encrypt(pt, key)
  elif crypt == 1:
    return aes_cbc_encrypt(pt, key, iv)

def main():
  print(aes_rand_encrypt(b'A'*80))

if __name__ == '__main__':
  sys.exit(main())

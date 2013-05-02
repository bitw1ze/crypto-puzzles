#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""
+========================+
|        ANSWER          |
+========================+

Plaintext: 

Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
"""

from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64decode
from helpers import chunks
from mycrypto import aes_ecb_encrypt, aes_ecb_decrypt, detect_ecb
import sys

key = Random.new().read(AES.block_size)
unknown_string = b64decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

def encryption_oracle(pt): 
  return aes_ecb_encrypt(pt+unknown_string, key)

def find_blocksize(encrypt_func):
  ct_len = len(encrypt_func(b'A'*1))
  for i in range(2, 512+1):
    _ = len(encrypt_func(b'A'*i))
    if (_ > ct_len):
      return _ - ct_len

  raise Exception("Could not detect block size!")

def bruteforce_ecb():
# detect block size and ECB mode
  block_size = find_blocksize(encryption_oracle)
  if not detect_ecb(encryption_oracle(b'A'*(3*block_size)), block_size):
    raise Exception("Cipher not in ECB mode")

# initialize things
  ciphertext = encryption_oracle(b'')
  plaintext = b'A'*block_size
  pt_block = b''

# the fun part
  for i in range(1, len(ciphertext)+1):
# calculate target ciphertext by correctly aligning things
    targetpt = plaintext[-(block_size-i%16):] if i % 16 != 0 else b''
    targetct = encryption_oracle(targetpt)
    targetpos = (len(plaintext) // block_size - 1)
    targetblk = chunks(targetct, block_size)[targetpos]

# brute-force one byte at a time by comparing each guess to target
    for j in range(0,255+1):
      guesspt = targetpt+pt_block+bytes([j])
      guessct = encryption_oracle(guesspt)
      guessblk = chunks(guessct, block_size)[0]
      if guessblk == targetblk:
        pt_block += bytes([j])
        if len(pt_block) == block_size:
          plaintext += pt_block
          pt_block = b''
        break

  # add any leftover bytes at the end
  if pt_block:
    plaintext += pt_block

  # Since I'm not trying to decrypt padding, I just strip off the last byte 
  return plaintext[block_size:-1]

def main():
  print(bruteforce_ecb().decode('utf8'))
    
if __name__ == '__main__':
  sys.exit(main())

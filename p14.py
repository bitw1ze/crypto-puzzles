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
from cryptlib import aes_ecb_encrypt, aes_ecb_decrypt
import sys

key = Random.new().read(AES.block_size)
random_prefix = Random.new().read(randint(0, 256))
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

def detect_ecb(cryptf, block_size):
  """Detect whether a given encryption function uses ECB mode"""

  entropy = Random.new()
  pt = entropy.read(block_size)
  pt1 = entropy.read(block_size) + pt
  pt2 = entropy.read(block_size) + pt
  ct1 = chunks(cryptf(pt1), block_size)
  ct2 = chunks(cryptf(pt2), block_size)

  return ct1[1] == ct2[1]

def decrypt_ecb():
  block_size = find_blocksize(encryption_oracle)
  if not detect_ecb(encryption_oracle, block_size):
    raise Exception("Cipher not in ECB mode")

  ciphertext = encryption_oracle(b'')
  plaintext = b'A'*block_size
  pt_block = b''
  i = 1
  for i in range(0, len(ciphertext)+1):
# calculate known plaintext bytes used to pad
    dummy = plaintext[-(block_size-i%16):] if i % 16 != 0 else b''
# get position of ciphertext block we want to break
    pos = (len(plaintext) // block_size - 1)*block_size
# ciphertext we are trying to match with our known plaintext 
    target = encryption_oracle(dummy)[pos:pos+block_size]
    for j in range(0,255+1):
      guess = dummy+pt_block+bytes([j])
      ct = encryption_oracle(guess)[:block_size]
      if ct == target:
        pt_block += bytes([j])
        if len(pt_block) == block_size:
          plaintext += pt_block
          pt_block = b''
        break

  # add any leftover bytes at the end
  if pt_block:
    plaintext += pt_block

  """ 
  If using pkcs7 padding, the last byte will always be 0x01 because the
  program assumes 0x01 is a valid byte, even though it is padding, and no
  other ciphertexts after that will be able to match the actual padding. 
  """ 

  return plaintext[block_size:-1]

def main():
  """
  process:
  1. detect block boundary and block size
    * to make things cleaner, initialize decrypted bytes to a block of padding bytes
  2. decrypt last block:
    a. shift plaintext so that its last byte is the first byte of the last block
    b. you know what the padding will be. brute-force the first byte
    c. brute-force the next bytes and so on until all the block is fully recovered
    d. prepend decrypted block to result bytestring
  3. decrypt the rest of the blocks:
    a. start by shifting the last block_size-1 decrypted bytes into the last block_size-1 bytes of the
    b. brute-force the first byte (last block_size-1 bytes are known)
    c. brute force the next bytes and so on until all the block is fully recovered
    d. prepend each decrypted block to result bytestring
  4. decrypt the last block
    a. last block will likely contain dummy characters
    b. fill block so that it only contains known dummy characters and target string
    c. brute-force starting from first unknown character
    d. discard dummy characters when prepending last block to result bytestring

  BETTER PROCESS:
  Find out where the plaintext we want begins
  1. call oracle function with incremental dummy text until block boundary is found
  2. store the cipehrtext and OFFSET that causes a block of padding to be added to the end
  3. generate the ciphertext with the same amount of a different dummy character
  4. compare to the ciphertext in #2 and find the POS of the differing block
  5. modify the original brute-force function:
    a. compare ciphertexts beginning at POS when decrypting byte-by-byte. 
    b. prepend brute-force attempts with OFFSET dummy bytes for alignment

  """

  print(decrypt_ecb().decode('utf8'))
    
if __name__ == '__main__':
  sys.exit(main())

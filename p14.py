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
from random import randint
from base64 import b64decode
from helpers import chunks
from mycrypto import aes_ecb_encrypt, aes_ecb_decrypt
from p8 import detect_ecb
import sys

key = Random.new().read(AES.block_size)
random_prefix = Random.new().read(randint(0, 256))
unknown_string = b64decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

def encryption_oracle(pt): 
  return aes_ecb_encrypt(random_prefix+pt+unknown_string, key)

def find_blocksize(cryptf):
  ct_len = len(cryptf(b'A'*1))
  for i in range(2, 512+1):
    _ = len(cryptf(b'A'*i))
    if (_ > ct_len):
      return _ - ct_len

  raise Exception("Could not detect block size!")

def find_known_index(cryptf):
  """
  Find the index of our known plaintext in the ciphertext output, given the
    encryption oracle cryptf.

  Returns:
    blocknum -- index of block where our plaintext begins
    offset -- N bytes to get known plaintext to start on the block boundary
  """
  ct1 = cryptf(b'A')
  ct2 = cryptf(b'B')
  bsz = find_blocksize(cryptf)

  # find where are plaintext block is by comparing two ciphertexts with equal size inputs
  blocknum = -1
  for i, (blk1, blk2) in enumerate(zip(chunks(ct1, bsz), chunks(ct2, bsz))):
    if blk1 != blk2:
      blocknum = i + 1
      break
  else:
    raise Exception("Could not find delta block!")

  nextblock = chunks(ct1, bsz)[blocknum]

  # find offset by creating blocks of equal size but different last byte
  # when the next block differs, we know we've passed a block boundary
  offset = -1
  for i in range(bsz+1):
    nextblock1 = chunks(cryptf(b'A'*i+b'A'), bsz)[blocknum]
    nextblock2 = chunks(cryptf(b'A'*i+b'B'), bsz)[blocknum]
    if nextblock1 != nextblock2:
      offset = i
      break
  else:
    raise Exception("Could not find alignment offset!")

  return blocknum, offset

"""

Apply our chosen plaintext attack where blocknum is the start of our known
plaintext in the ciphertext output and offset is the number of bytes from the
beginning of our known plaintext to a block boundary

"""

def bruteforce_ecb(blocknum, offset):
  blksz = find_blocksize(encryption_oracle)
  blockpos = blocknum*blksz
  if not detect_ecb(encryption_oracle(b'A'*(3*blksz))):
    raise Exception("Cipher not in ECB mode")

  ciphertext = encryption_oracle(b'')
  plaintext = b'B'*blksz
  pt_block = b''
  for i in range(blockpos+1, len(ciphertext)+offset):
# calculate known plaintext bytes used to pad
    dummy = b'A'*offset

    targetpt = dummy+plaintext[-(blksz-i%16):] if i % 16 != 0 else dummy
# ciphertext we are trying to match with our known plaintext 
    targetct = encryption_oracle(targetpt)
# get position of ciphertext block we want to break
    targetno = (len(plaintext) // blksz - 1) + blocknum
    targetblk = chunks(targetct, blksz)[targetno]

    for j in range(0,255+1):
      guesspt = targetpt+pt_block+bytes([j])
      guessct = encryption_oracle(guesspt)
      guessblk = chunks(guessct, blksz)[blocknum]
      if guessblk == targetblk:
        pt_block += bytes([j])
        if len(pt_block) == blksz:
          plaintext += pt_block
          pt_block = b''
        break

  # add any leftover bytes at the end
  if pt_block:
    plaintext += pt_block

  return plaintext[blksz:-1]


def bruteforce_ecb_randprefix():
  blocknum, offset = find_known_index(encryption_oracle)
  return bruteforce_ecb(blocknum, offset)


def main():
  """
  Steps:
  Find out where the plaintext we want begins
  1. call oracle function with incremental dummy text until block boundary is found
  2. store the cipehrtext and OFFSET that causes a block of padding to be added to the end
  3. generate the ciphertext with the same amount of a different dummy character
  4. compare to the ciphertext in #2 and find the POS of the differing block
  5. modify the original brute-force function:
    a. compare ciphertexts beginning at POS when decrypting byte-by-byte. 
    b. prepend brute-force attempts with OFFSET dummy bytes for alignment

  """

  print(bruteforce_ecb_randprefix().decode('utf8'))
    
if __name__ == '__main__':
  sys.exit(main())

from time import sleep
from Crypto import Random
from Crypto.Cipher import AES
from random import randint
from p7 import aes_ecb_encrypt, aes_ecb_decrypt
from p10 import aes_cbc_encrypt, aes_cbc_decrypt
from base64 import b64decode
from p8 import chunks
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

def detect_ecb(cryptf, block_size):
  """Detect whether a given encryption function uses ECB mode"""

  entropy = Random.new()
  pt = entropy.read(block_size)
  pt1 = entropy.read(block_size) + pt
  pt2 = entropy.read(block_size) + pt
  ct1 = chunks(cryptf(pt1), block_size)
  ct2 = chunks(cryptf(pt2), block_size)

  return ct1[1] == ct2[1]

def decrypt_ecb_block():
  """ """

def decrypt_ecb():
  block_size = find_blocksize(encryption_oracle)
  if not detect_ecb(encryption_oracle, block_size):
    raise Exception("Cipher not in ECB mode")

  ciphertext = encryption_oracle(b'')
  decrypted = b'A'*block_size
  cur = b''
  i = 1
  while len(ciphertext) != len(decrypted[block_size:]):
    dummy = decrypted[-(block_size-i%16):] if i % 16 != 0 else b''
    pos = (len(decrypted) // block_size - 1)*block_size
    target = encryption_oracle(dummy)[pos:pos+block_size]
    for j in range(0,255+1):
      guess = dummy+cur+bytes([j])
      ct = encryption_oracle(guess)[:block_size]
      if ct == target:
        cur += bytes([j])
        if len(cur) == block_size:
          decrypted += cur
          cur = b''
        break
    i += 1

  return decrypted[block_size:]

def main():
  '''
  plaintext = b'A'*80
  ciphertext = encryption_oracle(plaintext)
  print("ECB mode") if detect_ecb(ciphertext) else print("CBC mode")
  '''
  print(decrypt_ecb())
    
if __name__ == '__main__':
  sys.exit(main())

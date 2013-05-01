from Crypto.Cipher import AES
from helpers import chunks, flatten, identity
from itertools import cycle

def pkcs7_pad(msg, blocksize):
  padlen = blocksize - len(msg) % blocksize
  return bytearray(msg) + bytearray([padlen]*padlen)

def pkcs7_unpad(msg, blocksize):
  padlen = msg[-1]
  if padlen > blocksize or msg[-padlen:] != bytes([padlen])*padlen:
    raise Exception("Invalid padding! I sure hope you MAC'd already...")

  return msg[:-padlen]

def fixed_xor(msg1, msg2):
  if len(msg1) != len(msg2):
    raise Exception("Buffers are not same size!")

  return bytearray([a ^ b for (a,b) in zip(msg1, msg2) ])

def xor_repeat_cipher(msg, key):
  return bytearray([m ^ k for m, k in zip(msg, cycle(key))])

def aes_ecb_encrypt(pt, key, padf=pkcs7_pad):
  if not padf:
    padf = identity
  return AES.new(key, AES.MODE_ECB).encrypt(bytes(padf(pt, AES.block_size)))

def aes_ecb_decrypt(ct, key, unpadf=pkcs7_unpad):
  if not unpadf:
    unpadf = identity
  return unpadf(AES.new(key, AES.MODE_ECB).decrypt(ct), AES.block_size)

def cbc_encrypt(pt, cipher, iv, padf=pkcs7_pad):
  """Encrypt plaintext bytes in CBC mode

  Arguments:
  pt -- Plaintext bytes to encrypt
  cipher -- cipher object used to encrypt (must expose encrypt(ciphertext)
    method and block_size member)
  iv -- Initializion vector
  padf -- Padding function to called before encryption. Must take two
    arguments: bytes to pad and block size, and it should return the padded
    bytes.

  Returns:
  Bytes encrypted in CBC mode
  
"""
  if not padf:
    padf = identity

  ct = [iv]
  pt = chunks(padf(pt, cipher.block_size), cipher.block_size)
  for i in range(len(pt)):
    ct += [cipher.encrypt(bytes(fixed_xor(pt[i], ct[i])))]
  return flatten(ct[1:])

def cbc_decrypt(ct, cipher, iv, unpadf=pkcs7_unpad):
  """Decrypt ciphertext bytes in CBC mode

  Arguments:
  ct -- Ciphertext bytes to decrypt
  cipher -- cipher object used to decrypt (must expose decrypt(ciphertext)
    method and block_size member)
  iv -- Initializion vector
  padf -- Padding function called after decryption. Must take two arguments:
    bytes to pad and block size, and it should return the padded bytes.

  Returns:
  Bytes encrypted in CBC mode
  
  """

  if not unpadf:
    unpadf = identity

  pt = []
  ct = [iv] + chunks(ct, cipher.block_size)
  for i in range(1, len(ct)):
    pt += [fixed_xor(ct[i-1], cipher.decrypt(ct[i]))]
  return unpadf(flatten(pt), cipher.block_size)

def aes_cbc_encrypt(pt, key, iv, padf=pkcs7_pad):
  return cbc_encrypt(pt, AES.new(key, AES.MODE_ECB), iv, padf)

def aes_cbc_decrypt(ct, key, iv, unpadf=pkcs7_unpad):
  return cbc_decrypt(ct, AES.new(key, AES.MODE_ECB), iv, unpadf)

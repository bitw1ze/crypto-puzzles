_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""

This module contains crypto-related functions I implemented that are commonly
used in the challenges.

"""

from Crypto.Cipher import AES
from helpers import chunks, flatten, identity
from itertools import cycle

class InvalidPadding(Exception):
    pass

def pkcs7_pad(msg, blocksize):
    padlen = blocksize - len(msg) % blocksize
    return bytes(bytearray(msg) + bytearray([padlen]*padlen))

def pkcs7_unpad(msg, blocksize):
    padlen = msg[-1]
    if padlen > blocksize or msg[-padlen:] != bytes([padlen])*padlen:
        raise InvalidPadding("Invalid padding! I sure hope you MAC'd already...")

    return bytes(msg[:-padlen])

def fixed_xor(msg1, msg2):
    if len(msg1) != len(msg2):
        raise Exception("Buffers are not same size!")

    return bytes(bytearray([ord(a) ^ ord(b) for (a,b) in zip(msg1, msg2)]))

def xor_repeat_cipher(msg, key):
    return bytes(bytearray([m ^ k for m, k in zip(msg, cycle(key))]))

def aes_ecb_encrypt(pt, key, padf=pkcs7_pad):
    if not padf:
        padf = identity
    return AES.new(key, AES.MODE_ECB).encrypt(padf(pt, AES.block_size))

def aes_ecb_decrypt(ct, key, unpadf=pkcs7_unpad):
    if not unpadf:
        unpadf = identity
    return unpadf(AES.new(key, AES.MODE_ECB).decrypt(ct), AES.block_size)

def aes_cbc_encrypt(pt, key, iv, padf=pkcs7_pad):
    if not padf:
        padf = identity

    return cbc_encrypt(padf(pt, AES.block_size), AES.new(key, AES.MODE_ECB), iv)

def aes_cbc_decrypt(ct, key, iv, unpadf=pkcs7_unpad):
    if not unpadf:
        unpadf = identity
    base_cipher = AES.new(key, AES.MODE_ECB)
    return unpadf(cbc_decrypt(ct, base_cipher, iv), AES.block_size)

def next_nonce(nonce):
    nonce = bytearray(nonce)
    carry = 0
    i = len(nonce)-1

    if nonce[i] == 255:
        carry = 1
        nonce[-1] = 0

    while carry != 0:
        i -= 1
        if nonce[i] == 255:
            nonce[i] = 0
        else:
            carry = 0

    return bytes(nonce)
        
def ctr_crypt(msg, cipher, nonce):
    ct = b''
    for blk in chunks(msg, cipher.block_size):
        ct += fixed_xor(cipher.encrypt(nonce)[:len(blk)], blk)
        nonce = next_nonce(nonce)
    return ct

def aes_ctr_crypt(msg, key, nonce):
    return ctr_crypt(msg, AES.new(key, AES.MODE_ECB), nonce)

def cbc_encrypt(pt, cipher, iv):
    """

    Encrypt plaintext bytes in CBC mode

    Arguments:
    pt     -- Plaintext bytes to encrypt
    cipher -- cipher object used to encrypt (must expose encrypt(ciphertext)
              method and block_size member)
    iv     -- Initializion vector
    padf   -- Padding function to called before encryption. Must take two
              arguments: bytes to pad and block size, and it should return the
              padded bytes.

    Returns:
              Bytes encrypted in CBC mode
    
    """

    ct = [iv]
    pt = chunks(pt, cipher.block_size)
    for i in range(len(pt)):
        ct += [cipher.encrypt(bytes(fixed_xor(pt[i], ct[i])))]
    return flatten(ct[1:])

def cbc_decrypt(ct, cipher, iv):
    """
    
    Decrypt ciphertext bytes in CBC mode

    Arguments:
    ct     -- Ciphertext bytes to decrypt
    cipher -- Cipher object used to decrypt (must expose decrypt(ciphertext)
              method and block_size member)
    iv     -- Initializion vector
    padf   -- Padding function called after decryption. Must take two 
              arguments: bytes to pad and block size, and it should return the
              padded bytes.

    Returns:
              Bytes encrypted in CBC mode
    
    """

    pt = []
    ct = [iv] + chunks(ct, cipher.block_size)
    for i in range(1, len(ct)):
        pt += [fixed_xor(ct[i-1], cipher.decrypt(ct[i]))]
    return flatten(pt)

def detect_ecb(ct, blksz):
    blocks = chunks(ct, blksz)
    for i in range(len(blocks)-1):
        if blocks[i] in blocks[i+1:]:
            return True
    return False

#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

""" See break_dat_block() for the bulk of what this is doing. """

from sys import exit
from random import randint
from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES
from helpers import chunks
from mycrypto import (aes_cbc_decrypt, aes_cbc_encrypt, 
                     pkcs7_pad, pkcs7_unpad, InvalidPadding)

key = None
IV = None
ciphertext = None

def init():
    global key, IV, ciphertext

    key = Random.new().read(AES.block_size)
    IV = Random.new().read(AES.block_size)
    plaintext = None
    with open('p17-input.txt') as fh:
        pts = fh.readlines()
        n = randint(0, len(pts) - 1)
        plaintext = b64decode(pts[n].encode('utf8'))

    ciphertext = aes_cbc_encrypt(plaintext, key, IV, pkcs7_pad)

def decryption_oracle(ct, iv):
    try:
        aes_cbc_decrypt(ct, key, iv, pkcs7_unpad)
        return True
    except InvalidPadding as e:
        return False

def break_dat_block(blk, iv):
    """

    This function allows us to decrypt one block at a time and ignore the rest
    of the ciphertext. We call the decryption oracle with the target block as
    the ciphertext and the previous block as the IV. I did it this way to make
    it cleaner. If in a real-world scenario you can't control the IV, this
    could be easily modified to just focus on modifying the correct block of
    ciphertext and feeding it into the decryption oracle without changing the
    IV.

    blk -- block we want to decrypt
    iv  -- block immediately preceeding blk (effectively the IV)

    """

    if len(blk) != len(iv):
        raise Exception("Size of block and IV must be equal")

    blksz = len(blk)
    iv = bytearray(iv)
    ct = blk

# I wish i could come up with better variable names. Sorry :(
# pt = X ^ iv
# where X = decrypt(blk) and IV is actually just the previous CT block
    pt = b''
    X = b''
    r = 0

    for i in range(0, blksz):
        target = blksz - i - 1
        pad = i+1
        c = iv[target]
        for r in range(0, 256):
            # hack for when we find valid padding but not the padding we want
            if i == 0 and r == c:
                continue
            iv[target] = r

            if decryption_oracle(ct, bytes(iv)):
                x = pad ^ r
                decrypted = x ^ c
                pt = bytes([decrypted]) + pt

                X = bytes([x]) + X
                for k in range(len(X)):
                    # adjust padding byte so next round it's valid
                    iv[target+k] = X[k] ^ (pad + 1)

                break

        else:
            # We should never get here ;)
            raise Exception("Your code is bad and you should feel bad")

    return pt

def padding_like_a_boss():
    plaintext = b''
    blksz = AES.block_size
    blocks = chunks(IV + ciphertext, blksz)
    for i in range(1, len(blocks)):
        plaintext += break_dat_block(blocks[i], blocks[i-1])

    return pkcs7_unpad(plaintext, blksz)
    
def main():
    init()
    plaintext = padding_like_a_boss()
    print(plaintext.decode('utf8'))
    
if __name__ == '__main__':
    exit(main())

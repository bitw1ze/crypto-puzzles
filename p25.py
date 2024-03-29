#!/usr/bin/env python3

''' Exploit random access read/write CTR to decrypt ciphertext without key 

This attack is implemented in a couple of ways.

slowdecrypt: edits one byte at a time, checking if the ciphertexts still match
fastdecrypt: recovers ciphertext by generating a dummy ciphertext and XORing
the known plaintext with the XOR of the original ciphertext and dummy
ciphertext '''

from base64 import b64decode
from sys import exit, stdout
from Crypto import Random
from mycrypto import aes_ctr_encrypt, aes_ctr_decrypt, fixed_xor

p25_key = Random.new().read(16)
p25_nonce = Random.new().read(16)

def edit(ciphertext, offset, newtext):

    pt = aes_ctr_decrypt(ciphertext, p25_key, p25_nonce)
    newpt = pt[:offset] + newtext + pt[offset+len(newtext):]
    return aes_ctr_encrypt(newpt, p25_key, p25_nonce)

def slowdecrypt(ciphertext):

    plaintext = b''
    for i in range(len(ciphertext)):
        for j in range(256):
            guess = bytes([j])
            ct = edit(ciphertext, i, guess)
            if ct[i] == ciphertext[i]:
                plaintext += guess
                stdout.write(guess.decode('utf8'))
                stdout.flush()
                break

    return plaintext

def fastdecrypt(ciphertext):

    pt = b'A'*len(ciphertext)
    ct = edit(ciphertext, 0, pt)
    plaintext = fixed_xor(pt, fixed_xor(ct, ciphertext))
    print(plaintext.decode('utf8'))

def main():

    ciphertext = None
    with open('p25-input.txt') as fh:
        ciphertext = aes_ctr_encrypt(bytes(fh.read(), 'utf8'), p25_key, p25_nonce)

    fastdecrypt(ciphertext)
    slowdecrypt(ciphertext)

if __name__ == '__main__':
    exit(main())

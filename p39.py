#!/usr/bin/env python3.2

from base64 import b16encode, b16decode
from sys import exit

# yes, i am this lazy
from fractions import gcd
from Crypto.PublicKey.pubkey import getStrongPrime

from helpers import *

def egcd(a, b):
    
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
def invmod(a, m):

    g, x, y = egcd(a, m)
    return x % m if g == 1 else 0

def rsa_encrypt_bytes(pubkey, message):

    return _rsa_crypt_bytes(pubkey, message)

def rsa_decrypt_bytes(privkey, message):

    return _rsa_crypt_bytes(privkey, message)

def _rsa_crypt_bytes(k, msg):

    k = (b2i(k[0]), b2i(k[1]))
    return i2b(_rsa_crypt(k, b2i(msg)))

def _rsa_crypt(k, msg):

    return pow(msg, k[0], k[1])

def generate_keypair_bytes(bits):

    pubkey, privkey = _generate_keypair(bits)
    return (i2b(pubkey[0]), i2b(pubkey[1])), (i2b(privkey[0]), i2b(privkey[1]))

def _generate_keypair(bits):

    e = 3
    while True:

        p = getStrongPrime(bits)
        q = getStrongPrime(bits)
        n = p * q
        et = (p-1)*(q-1)

        if gcd(et, e) == 1:
            break
    d = invmod(e, et)
    return ((e, n), (d, n))

def main():

    pubkey, privkey = generate_keypair_bytes(1024)
    print("e:", b2hs(pubkey[0]))
    print("d:", b2hs(privkey[0]))
    print("n:", b2hs(privkey[1]))
    message = b"I be tossin', enforcin', my style is awesome / I'm causin' more Family Feuds than Richard Dawson!"
    ciphertext = rsa_encrypt_bytes(pubkey, message)
    plaintext = rsa_decrypt_bytes(privkey, ciphertext)
    print("encrypted:", b2hs(ciphertext))
    print("decrypted:", b2u(plaintext))

if __name__ == '__main__':

    exit(main())

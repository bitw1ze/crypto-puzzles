#!/usr/bin/env python3.2

import sys

from helpers import b2hs, b2u
from myrsa import rsa_encrypt_bytes, rsa_decrypt_bytes, generate_keypair_bytes

def main():

    print("Let's encrypt a message!")
    print("Generating a 1024 bit public key...")
    KEY_SIZE = 1024
    pubkey, privkey = generate_keypair_bytes(KEY_SIZE)
    print("e:", b2hs(pubkey[0]))
    print("d:", b2hs(privkey[0]))
    print("n:", b2hs(privkey[1]))
    message = b"I be tossin', enforcin', my style is awesome / I'm causin' more Family Feuds than Richard Dawson!"
    ciphertext = rsa_encrypt_bytes(pubkey, message)
    plaintext = rsa_decrypt_bytes(privkey, ciphertext)
    print("=================== encrypted message ===================")
    print(b2hs(ciphertext))
    print("=================== decrypted message ===================")
    print(b2u(plaintext))

if __name__ == '__main__':

    sys.exit(main())

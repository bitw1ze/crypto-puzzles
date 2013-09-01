#!/usr/bin/env python3.2

import sys

from mydsa import dsa_generate_keypair, dsa_verify, P, Q, G, H, Signature
from helpers import *
from mymath import invmod
from Crypto.Random.random import randint

def dsa_sign_bad(privkey, message, p=P, q=Q, g=G):

    m = b2i(message)
    k = randint(1, q-1)
    r = pow(g, k, p) % q
    s = (invmod(k, q) * (H(message) + privkey.x * r)) % q

    return Signature(message, r, s)

def main():

    msg1 = b'Hello, world'
    msg2 = b'Goodbye, world'

    pubkey, privkey = dsa_generate_keypair()

    z = 9001
    r = pow(pubkey.y, z, P) % Q
    s = r * invmod(z, Q) % Q
    sig1 = Signature(msg1, r, s)

    z = 31337
    r = pow(pubkey.y, z, P) % Q
    s = r * invmod(z, Q) % Q
    sig2 = Signature(msg2, r, s)

    print(sig1)
    print(sig2)

    if dsa_verify(pubkey, sig2, g=P+1) and dsa_verify(pubkey, sig2, g=P+1):
        print("Valid signatures")
    else:
        print("Invalid signatures")

if __name__ == '__main__':
    sys.exit(main())

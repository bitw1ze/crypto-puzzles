#!/usr/bin/env python3.2

import sys
from collections import namedtuple

from Crypto.Random.random import randint
from hashlib import sha1
from helpers import *
from mymath import invmod

p=0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q=0xf4f47f05794b256174bba6e9b396a7707e563c5b
g=0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
MAX_K = 2**16

PublicKey = namedtuple("PublicKey", ["y"])
PrivateKey = namedtuple("PrivateKey", ["x"])
Signature = namedtuple("Signature", ["r", "s"])

H = lambda _: b2i(sha1(_).digest())

def dsa_generate_keypair():

    x = randint(1, q-1)
    y = pow(g, x, p)

    return PublicKey(y), PrivateKey(x)


def dsa_sign(privkey, message):

    m = b2i(message)
    k = randint(1, MAX_K)
    r = pow(g, k, p) % q
    while r == 0:
        k = randint(1, MAX_K)
        r = pow(g, k, p) % q

    s = (invmod(k, q) * (H(message) + privkey.x * r)) % q

    # If s is zero, you should start over, but that will probably never
    # happen (i'm lazy).

    return Signature(r, s)

def dsa_verify(pubkey, message, sig):

    m = b2i(message)

    w = invmod(sig.s, q)
    u_1 = (H(message) * w) % q
    u_2 = (sig.r * w) % q
    v = ((pow(g, u_1, p) * pow(pubkey.y, u_2, p)) % p) % q
    return v == sig.r

def dsa_test():

    message = b"BITCOIN RABBIT LIKES TO PARTY"
    pubkey, privkey = dsa_generate_keypair()
    sig = dsa_sign(privkey, message)
    assert(dsa_verify(pubkey, message, sig))

def main():

    message = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"
    sig = Signature(r=0x548099063082341131477253921760299949438196259240,
                    s=0x857042759984254168557880549501802188789837994940)

    # Let's brute-force each k value until we find the right privkey
    x = -1
    for k in range(MAX_K):
        x = ((sig.s*k - H(message)) * invmod(sig.r, q)) % q
        if dsa_sign(PrivateKey(x), message).r == sig.r:
            break

    if x != -1:
        print("Found private key!")
        print(x)
        # 1257023921680741639141327515185799093077904406672

if __name__ == '__main__':
    sys.exit(main())



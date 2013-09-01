from collections import namedtuple
from Crypto.Random.random import randint
from hashlib import sha1
from helpers import *
from mymath import invmod

P=0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
Q=0xf4f47f05794b256174bba6e9b396a7707e563c5b
G=0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

PublicKey = namedtuple("PublicKey", ["y"])
PrivateKey = namedtuple("PrivateKey", ["x"])
Signature = namedtuple("Signature", ["m", "r", "s"])

H = lambda _: b2i(sha1(_).digest())

def dsa_generate_keypair(p=P, q=Q, g=G):

    x = randint(1, q-1)
    y = pow(g, x, p)

    return PublicKey(y), PrivateKey(x)

def dsa_sign(privkey, message, p=P, q=Q, g=G):

    s = 0
    while s == 0:
        r = 0
        while r == 0:
            k = randint(1, q-1)
            r = pow(g, k, p) % q

        s = (invmod(k, q) * (H(message) + privkey.x * r)) % q

    return Signature(message, r, s)

def dsa_verify(pubkey, sig, p=P, q=Q, g=G):

    m = b2i(sig.m)

    w = invmod(sig.s, q)
    u_1 = (H(sig.m) * w) % q
    u_2 = (sig.r * w) % q
    v = ((pow(g, u_1, p) * pow(pubkey.y, u_2, p)) % p) % q
    return v == sig.r

def dsa_test():

    message = b"BITCOIN RABBIT LIKES TO PARTY"
    pubkey, privkey = dsa_generate_keypair()
    sig = dsa_sign(privkey, message)
    print(message)
    print(pubkey)
    print(privkey)
    print(sig)
    assert(dsa_verify(pubkey, message, sig))


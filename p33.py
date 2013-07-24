#!/usr/bin/env python3.2

import sys
import struct
from math import log
from hashlib import sha256
from base64 import b16decode, b16encode

from Crypto.Random import random

class DHE:

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    def generate_keypair(self, nbits=576, g=g, p=p):
        ''' Generate a private and public key to be used for the DHE '''

        n = random.getrandbits(nbits)
        return n, pow(g, n, p)

    def negotiate_key(self, privkey, pubkey, keyfunc=None, p=p):
        ''' Negotiate a shared secret. 
        
        Returns a session key and, if implemented in the keyfunc, a MAC key '''

        if keyfunc is None:
            keyfunc = self.key_mac_128

        secret = pow(pubkey, privkey, p)
        secret = bytes("%x" % secret, 'utf8')
        if len(secret) % 2 != 0:
            secret = b'0' + secret
        secret = b16decode(secret, casefold=True)
        return keyfunc(secret)

    def key_mac_128(self, secret):
        ''' return a 128-bhit session key and 128-bit MAC key '''

        digest = sha256(secret).digest()
        return digest[:16], digest[16:]

    def key_128(self, secret):
        ''' return a 128-bit session key '''

        digest = sha256(secret).digest()
        return digest[:16]


def main():

    dh = DHE()
    a, A = dh.generate_keypair()
    b, B = dh.generate_keypair()
    s1 = dh.negotiate_key(a, B)
    s2 = dh.negotiate_key(b, A)
    assert(s1 == s2)
    session_key, mac_key = s1

    print("Successfully negotiated a secret with DH")
    print("Session key: " + str(b16encode(session_key), 'utf8'))
    print("MAC key:     " + str(b16encode(mac_key), 'utf8'))

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3.2

from base64 import b16encode, b16decode
from functools import reduce
import operator

from helpers import *
from myrsa import generate_keypair_bytes, rsa_encrypt_bytes
from mymath import invmod, root3

def main():

    KEY_SIZE = 512
    msg = b"SUPER SECRET"
    pubkeys = [generate_keypair_bytes(KEY_SIZE)[0] for i in range(3)]
    cts = [b2i(rsa_encrypt_bytes(k, msg)) for k in pubkeys]
    moduli = [b2i(i[1]) for i in pubkeys]
    crt = 0

    for i in range(3):
        m_s = reduce(operator.mul, [moduli[j] if i != j else 1 for j in range(3)], 1)
        crt += (cts[i] * m_s * invmod(m_s, moduli[i]))

    n012 = reduce(operator.mul, [m for m in moduli], 1)
    crt = crt % n012
    plaintext = root3(crt)
    print(i2s(plaintext))

if __name__ == '__main__':

    exit(main())

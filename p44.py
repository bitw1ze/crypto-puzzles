#!/usr/bin/env python3.2

import sys

from hashlib import sha1
from helpers import *
from mymath import invmod
from mydsa import sign, generate_keypair, H, Q, Signature, PrivateKey

def recover_nonce():

    infile = "p44-input.txt" if len(sys.argv) == 1 else sys.argv[1]
    r = 0
    s = 0
    signed = []

    with open(infile) as fh:
        for i, line in enumerate(fh.readlines()):
            line = line[:-1]
            if i % 4 == 0:
                message = s2b(line)
            elif i % 4 == 1:
                s = int(line)
            elif i % 4 == 2:
                r = int(line)
                signed.append(Signature(message, r, s))

    found_key = False
    for i, z1 in enumerate(signed):
        for j, z2 in enumerate(signed):
            if i == j or z1.r != z2.r:
                continue

            m1, s1 = H(z1.m), z1.s
            m2, s2 = H(z2.m), z2.s
            k = ((m1-m2) * invmod((s1-s2)%Q, Q)) % Q
            x = ((z1.s*k - m1) * invmod(z1.r, Q)) % Q
            _sig = sign(PrivateKey(x), z1.m)
            key_digest = sha1(bytes(hex(x)[2:], 'utf8')).hexdigest()
            if key_digest == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52':
                return x
    else:
        raise Exception("Failed to find key!")


def main():

    x = recover_nonce()
    print("Found your private key!")
    print(hex(x)[2:])
        
if __name__ == '__main__':
    sys.exit(main())

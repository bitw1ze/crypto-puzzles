#!/usr/bin/env python3.2

import sys
from hashlib import sha1

from mymath import invmod
from mydsa import dsa_generate_keypair, dsa_sign, dsa_verify, Q, H, Signature, PrivateKey, PublicKey
from helpers import i2b,s2b

q = Q
y=0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
pubkey = PublicKey(y)


def dsa_bruteforce():

    message =  b"For those that envy a MC it can be hazardous to your health\n"
    message += b"So be friendly, a matter of life and death, "
    message += b"just like a etch-a-sketch\n"
    sig = Signature(m=message,
                    r=548099063082341131477253921760299949438196259240,
                    s=857042759984254168557880549501802188789837994940)

    for k in range(2**16):
        x = ((sig.s*k - H(message)) * invmod(sig.r, q)) % q
        s = dsa_sign(PrivateKey(x), message)
        if dsa_verify(pubkey, s):
            _x = hex(x)[2:]
            fingerprint = sha1(s2b(_x)).hexdigest()
            print("Found key!")
            print("x = %s" % _x)
            print("fingerprint: %s" % fingerprint)
            break
    else:
        raise Exception("Failed to find key")

def main():

    dsa_bruteforce()
    
if __name__ == '__main__':
    sys.exit(main())



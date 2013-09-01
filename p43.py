#!/usr/bin/env python3.2

import sys

from mymath import invmod
from mydsa import dsa_sign, Q, H, Signature, PrivateKey

q = Q

def dsa_bruteforce():

    message =  b"For those that envy a MC it can be hazardous to your health\n"
    message += b"So be friendly, a matter of life and death, "
    message += b"just like a etch-a-sketch\n"
    sig = Signature(m=message,
                    r=0x548099063082341131477253921760299949438196259240,
                    s=0x857042759984254168557880549501802188789837994940)

    # Let's brute-force each k value until we find the right privkey
    MAX_K = 2**16
    x = -1
    for k in range(MAX_K):
        x = ((sig.s*k - H(message)) * invmod(sig.r, q)) % q
        if dsa_sign(PrivateKey(x), message).r == sig.r:
            break

    if x != -1:
        print("Found private key!")
        print(x)
        # 1257023921680741639141327515185799093077904406672

def main():

    dsa_bruteforce()
    
if __name__ == '__main__':
    sys.exit(main())



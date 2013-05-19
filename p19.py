#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""

I'm not really sure the instructions are asking for. My first solution to
this problem was actually the solution for #20 because it was the obvious way
of doing it. I decided to do a chosen plaintext attack for this problem. Hope
that'll do.

"""

from sys import exit
from base64 import b64decode
from Crypto import Random
from Crypto.Cipher import AES
from mycrypto import aes_ctr_crypt

p19_key = Random.new().read(AES.block_size)

def generate_ciphertexts():
    pts = None
    with open('p19-input.txt') as fh:
        pts = [b64decode(pt.encode('utf8')) for pt in fh.readlines()]

    cts = []
    for pt in pts:
        cts.append(ctr_fixed_nonce(pt))

    return cts

def ctr_fixed_nonce(pt):
    nonce = b"\x00" * AES.block_size
    return aes_ctr_crypt(pt, p19_key, nonce)

def break_fail_ctr(cts):
    pts = []

    for ct in cts:
        pts.append(_break_fail_ctr(ct))
        
    return pts

def _break_fail_ctr(ct):
    pt = b''
    for i in range(len(ct)):
        for j in range(256):
            guess = bytes([j])
            if ct[i] == ctr_fixed_nonce(pt+guess)[i]:
                pt += guess
                break

    return pt

def main():
    ciphertexts = generate_ciphertexts()
    plaintexts = break_fail_ctr(ciphertexts)
    for pt in plaintexts:
        print(pt.decode("utf8"))

if __name__ == '__main__':
    exit(main())


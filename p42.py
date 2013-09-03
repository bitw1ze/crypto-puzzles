#!/usr/bin/env python3.2

import sys
from helpers import i2b, b2i, b2hs
from mymath import root3

from myrsa import generate_keypair_bytes, verify_bytes, Hb

HASH_PREFIX = b"SHA1"
HASH_LENGTH = 20

def pkcs1v1_5_pad_evil(m):

    out = b'\x01\xff\x00'
    out += HASH_PREFIX # I would use ASN.1 encoding, but #YOLO
    out += Hb(m)
    return out

def pkcs1v1_5_unpad_insecure(data):

    if data[:2] != b'\x01\xff':
        raise badPadding

    cur = 2
    while data[cur] == b'\xff':
        cur += 1

    if data[cur] != 0:
        raise badPadding
    cur += 1

    if data[cur:cur+len(HASH_PREFIX)] != HASH_PREFIX:
        raise badPadding
    cur += len(HASH_PREFIX)

    return data[cur:cur+HASH_LENGTH]

def main():

    message = b'hi mom'
    pubkey, privkey = generate_keypair_bytes(bits=1024, e=3)

    # create our forged signature
    h = Hb(message)
    padded = pkcs1v1_5_pad_evil(message)
    padded += b'\x10'
    padded += b'\x00'*55    # this seems like a good number
    fake_sig = i2b(root3(b2i(padded)))

    if verify_bytes(pubkey, message, fake_sig, unpadf=pkcs1v1_5_unpad_insecure):
        print("Successfully forged signature!")
        print()
        print("Padded data:")
        print(padded)
        print()
        print("Signature:")
        print(b2hs(fake_sig))
    else:
        print("Failed to forge signature :(")

if __name__ == '__main__':
    sys.exit(main())

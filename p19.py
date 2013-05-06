from sys import exit
from base64 import b64decode
from mycrypto import aes_ctr_crypt
from Crypto.Cipher import AES
from Crypto import Random

trigrams = [ "the", "and", "tha", "ent", "ing", "ion", "tio", "for", 
             "nde", "has", "nce", "edt", "tis", "oft", "sth", "men" ]


def main():
    pts = None
    with open('p19-input.txt') as fh:
        pts = [b64decode(pt.encode('utf8')) for pt in fh.readlines()]

    key = Random.new().read(AES.block_size)
    nonce = b"\x00" * AES.block_size
    cts = []
    for pt in pts:
        print(pt)
        cts += [aes_ctr_crypt(pt, key, nonce)]

if __name__ == '__main__':
    exit(main())

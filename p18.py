from mycrypto import aes_ctr_crypt
from base64 import b64encode
from sys import exit
from Crypto.Cipher import AES
from Crypto import Random

def main():
    pts = [
        "been spending most our lives",
        "living in a ganster's paradise",
        "nuclear launch codes",
        "the FBI will never catch me, my address is @!#*&%)!@#",
        "the quieter you are the more you are able to hear"
    ]
    cts = []

    key = Random.new().read(AES.block_size)
    nonce = Random.new().read(AES.block_size)

    print("Ciphertexts")
    print("-----------")
    for pt in pts:
        cts += [aes_ctr_crypt(bytes(pt, 'utf8'), key, nonce)]
        print(b64encode(cts[-1]).decode('utf8'))

    print("\nPlaintexts")
    print("-----------")
    for ct in cts:
        print(aes_ctr_crypt(ct, key, nonce).decode('utf8'))

if __name__ == '__main__':
    exit(main())

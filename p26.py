#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"


from Crypto.Cipher import AES
from Crypto import Random
from mycrypto import aes_ctr_encrypt, aes_ctr_decrypt
import sys

p26_key = Random.new().read(AES.block_size)
p26_nonce = Random.new().read(AES.block_size)

def encrypt_data(data):
    if ';' in data or '=' in data:
        raise Exception("Invalid userdata")

    data =  b"comment1=cooking%20MCs;userdata=" + bytes(data, 'utf8')
    data += b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_ctr_encrypt(data, p26_key, p26_nonce)

def decrypt_data(data):
    pt = aes_ctr_decrypt(data, p26_key, p26_nonce)
    return pt

def is_admin(ct):
    pairs = decode(decrypt_data(ct).decode('utf8', 'ignore'))
    return 'admin' in pairs.keys() and pairs['admin'] == 'true'

def decode(s):
    return dict([(k,v) for k,v in [p.split('=') for p in s.split(';')]])

def admin_get():
    ct = encrypt_data("fooba|admin|true")
    pos1 = 32+5
    pos2 = 32+11
    for i in range(256):
        for j in range(256):
            try:
                chosen_ct = (ct[:pos1] + bytes([i]) + ct[pos1+1:pos2] +
                            bytes([j]) + ct[pos2+1:])
                if is_admin(chosen_ct):
                    return chosen_ct
            except Exception as e:
                pass
        else:
            continue
        break
    else:
        raise Exception("Couldn't get admin! :(")

def main():
    result = decode(decrypt_data(admin_get()).decode('utf8', 'ignore'))
    print("Got admin! Proof:\n%s" % result)

if __name__ == '__main__':
    sys.exit(main())

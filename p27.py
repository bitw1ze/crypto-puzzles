#!/usr/bin/env  python3.2

_author_  = "Gabe Pike"
_email_   = "gpike@isecpartners.com"

from sys import exit
from base64 import b16decode, b16encode
from textwrap import dedent
from Crypto.Cipher import AES
from Crypto import Random
from mycrypto import (aes_cbc_encrypt, aes_cbc_decrypt, 
                     pkcs7_pad, pkcs7_unpad,
                     fixed_xor, 
                     InvalidPadding)

p27_key = Random.new().read(AES.block_size)
p27_iv  = p27_key

class InvalidAscii(Exception):
    pass

def encrypt_data(data):
    if ';' in data or '=' in data:
        raise Exception("Invalid userdata")

    data =  b"comment1=cooking%20MCs;userdata=" + bytes(data, 'utf8')
    data += b";comment2=%20like%20a%20pound%20of%20bacon"
    return aes_cbc_encrypt(data, p27_key, p27_iv, pkcs7_pad)

def decrypt_data(data):
    pt = aes_cbc_decrypt(data, p27_key, p27_iv, pkcs7_unpad)
    for ch in pt:
        if ch > 127:
            raise InvalidAscii(dedent("""Bad decrypt! I'm going to print the
                decrypted data for no particular reason now: %s""") %
                b16encode(pt).decode('utf8'))

    return pt

def decode_data(s):
    return dict([(k,v) for k,v in [p.split('=') for p in s.split(';')]])

def admin_get():
    key = None
    ct = encrypt_data("A"*16)
    ct = ct[:16] + b"\x00"*16 + ct[:16] + b"\x00"*16
    for i in range(1, 256):
        try:
            decrypt_data(ct)
        except InvalidPadding as e:
            # Since padding is enabled, we must find a ciphertext with correct
            # padding by fiddling with the last byte of the 2nd to last block.
            ct = ct[:16] + b"\x00"*16 + ct[:16] 
            ct += b"\x00"*15+bytes([i]) + b"\x00"*16
            continue
        except InvalidAscii as e:
            e = str(e)
            index = e.find(':') + 2
            pt = bytes(e[index:], 'utf8')
            pt = b16decode(pt)
            key = fixed_xor(pt[:16], pt[32:48])
            data =  b'comment1=it is happening;'
            data += b'comment2=there is no hope;'
            data += b'comment3=you could have stopped this;'
            data += b'comment4=but now it is too late;'
            data += b'userdata=shhhhh, only dreams now;'
            data += b'admin=true'
            return aes_cbc_encrypt(data, key, key, pkcs7_pad)

    raise Exception("Your code is bad and you should feel bad")

def main():
    result = decode_data(decrypt_data(admin_get()).decode('utf8', 'ignore'))
    print("Got admin! Proof:")
    print(result)

if  __name__ == '__main__':
    exit(main())

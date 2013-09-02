from fractions import gcd
from collections import namedtuple 
from Crypto.PublicKey.pubkey import getStrongPrime

from mymath import invmod
from helpers import i2b, b2i
from hashlib import sha1

E = 65535

Hb = lambda x: sha1(x).digest()             # hash bytes
Hn = lambda x: b2i(sha1(i2b(x)).digest())   # hash num

def sign_bytes(privkey, message):

    return _crypt_bytes(privkey, Hb(message))

def sign_num(privkey, message):

    return _crypt(privkey, Hn(message))

def verify_bytes(pubkey, message, signature):

    return _crypt_bytes(pubkey, signature) == Hb(message)

def verify_num(pubkey, message, signature):

    return _crypt(pubkey, signature) == Hn(message)

def encrypt_bytes(pubkey, message):

    return _crypt_bytes(pubkey, message)

def decrypt_bytes(privkey, message):

    return _crypt_bytes(privkey, message)

def _crypt_bytes(k, msg):

    k = (b2i(k[0]), b2i(k[1]))
    msg = b2i(msg)
    return i2b(_crypt(k, msg))

def encrypt_num(k, msg):

    return _crypt(k, msg)

def decrypt_num(k, msg):

    return _crypt(k, msg)

def _crypt(k, msg):

    return pow(msg, k[0], k[1])

def generate_keypair_bytes(bits, e=E):

    pubkey, privkey = generate_keypair_num(bits, e)
    return (i2b(pubkey[0]), i2b(pubkey[1])), (i2b(privkey[0]), i2b(privkey[1]))

def generate_keypair_num(bits, e=E):

    while True:

        p = getStrongPrime(bits)
        q = getStrongPrime(bits)
        n = p * q
        et = (p-1)*(q-1)

        if gcd(et, e) == 1:
            break
    d = invmod(e, et)
    return ((e, n), (d, n))

def _test_signing():

    message = b'Hello world!'
    pubkey, privkey = generate_keypair_bytes(bits=1024)
    sig = sign_bytes(privkey, message)
    assert(verify_bytes(pubkey, message, sig))

if __name__ == '__main__':
    _test_signing()

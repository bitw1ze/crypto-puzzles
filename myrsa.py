from fractions import gcd
from Crypto.PublicKey.pubkey import getStrongPrime

from mymath import invmod
from helpers import i2b, b2i

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

def generate_keypair_bytes(bits, e):

    pubkey, privkey = generate_keypair_num(bits, e)
    return (i2b(pubkey[0]), i2b(pubkey[1])), (i2b(privkey[0]), i2b(privkey[1]))

def generate_keypair_num(bits, e=65535):

    while True:

        p = getStrongPrime(bits)
        q = getStrongPrime(bits)
        n = p * q
        et = (p-1)*(q-1)

        if gcd(et, e) == 1:
            break
    d = invmod(e, et)
    return ((e, n), (d, n))


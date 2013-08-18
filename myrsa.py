# yes, i am this lazy
from fractions import gcd
from Crypto.PublicKey.pubkey import getStrongPrime

from mymath import invmod
from helpers import i2b, b2i

def rsa_encrypt_bytes(pubkey, message):

    return _rsa_crypt_bytes(pubkey, message)

def rsa_decrypt_bytes(privkey, message):

    return _rsa_crypt_bytes(privkey, message)

def _rsa_crypt_bytes(k, msg):

    k = (b2i(k[0]), b2i(k[1]))
    msg = b2i(msg)
    return i2b(_rsa_crypt(k, msg))

def _rsa_crypt(k, msg):

    return pow(msg, k[0], k[1])

def generate_keypair_bytes(bits):

    pubkey, privkey = _generate_keypair(bits)
    return (i2b(pubkey[0]), i2b(pubkey[1])), (i2b(privkey[0]), i2b(privkey[1]))

def _generate_keypair(bits):

    e = 3
    while True:

        p = getStrongPrime(bits)
        q = getStrongPrime(bits)
        n = p * q
        et = (p-1)*(q-1)

        if gcd(et, e) == 1:
            break
    d = invmod(e, et)
    return ((e, n), (d, n))


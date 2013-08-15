#!/usr/bin/env python3.2

from fractions import gcd

def egcd(a, b):
    
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
def invmod(a, m):

    g, x, y = egcd(a, m)
    return x % m if g == 1 else 0

def rand_bignum():

    pass

def rsa_encrypt(pubkey, message):
    print("ENCRYPTING")
    print("e: %d" % pubkey[0])
    print("n: %d" % pubkey[1])

    return pow(message, pubkey[0], pubkey[1])

def rsa_decrypt(privkey, message):
    print("DECRYPTING")
    print("d: %d" % privkey[0])
    print("n: %d" % privkey[1])

    return pow(message, privkey[0], privkey[1])

def generate_keypair():

    p = 98509491925355636814624722856481164974976024092749
    q = 64859058853096061872133820986796618624188088272603
    n = p * q
    et = (p-1)*(q-1)
    e = 3
    while True:
        if gcd(et, e) == 1:
            break
        e += 1
    e = 5860433983155613419396388808578642169570584742076441436113747269795218700332009569861122501530578287
    d = 4370212695082959697644347549013759337535856224600700845783256501293135585098885497690009531778314671
    return ((e, n), (d, n))

pubkey, privkey = generate_keypair()
message = 42
print(message)
ciphertext = rsa_encrypt(pubkey, message)
print(ciphertext)
plaintext = rsa_decrypt(privkey, message)
print(plaintext)

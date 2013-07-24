#!/usr/bin/env python3.2

import os
from hashlib import sha256
from hmac import HMAC
from base64 import b16encode

# client and server
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
password=b'qwerty'

# server generates v from the password verifier and DH group params
salt = os.urandom(8)

# client sends username and A to server
username='admin'
a = int(str(b16encode(os.urandom(72)), 'utf8'), 16)
A = pow(g, a, N)

# server sends B to client
b = int(str(b16encode(os.urandom(72)), 'utf8'), 16)
B = pow(g, b, N)

# client and server agree on random 'u' value
u = int(b16encode(os.urandom(16)), 16)

# client calculates auth string
xH = sha256(salt + password).hexdigest()
x = int(xH, 16)
S = pow(B, a + u * x, N)
K = sha256(bytes(str(S), 'utf8')).digest()
token = HMAC(K, salt, sha256).digest()

# server brute-force time
with open('wordlist.txt', 'r') as fh:
    words = fh.read().splitlines()

for word in words:
    password = bytes(word, 'utf8')
    xH = sha256(salt + password).hexdigest()
    x = int(xH, 16)
    v = pow(g, x, N)
    S = pow(A * pow(v, u, N), b, N)
    K = sha256(bytes(str(S), 'utf8')).digest()

    if token == HMAC(K, salt, sha256).digest():
        print('[+] %s:%s ' % (username, word))
        break
else:
    print('[-] wordlist exhausted')

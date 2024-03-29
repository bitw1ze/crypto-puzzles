#!/usr/bin/env python3.2

import os
from hashlib import sha256
from hmac import HMAC
from base64 import b16encode

# client and server
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
username=b'admin'
password=b'muhpassword'

# server generates v from the password verifier and DH group params
salt = os.urandom(8)
xH = sha256(salt + password).hexdigest()
x = int(xH, 16)
v = pow(g, x, N)

# client sends username and A to server
a = int(str(b16encode(os.urandom(72)), 'utf8'), 16)
A = pow(g, a, N)

# server sends B to client
b = int(str(b16encode(os.urandom(72)), 'utf8'), 16)
B = k*v + pow(g, b, N)

# client and server calculate 'u' from the public keys
uH = sha256(bytes(str(A) + str(B), 'utf8')).hexdigest()
u = int(uH, 16)

# client calculates K 
xH = sha256(salt + password).hexdigest()
x = int(xH, 16)
S = pow(B - k * pow(g, x, N), a + u * x, N)
K = sha256(bytes(str(S), 'utf8')).digest()

# server calculates K
S = pow(A * pow(v, u, N), b, N)
K = sha256(bytes(str(S), 'utf8')).digest()

# client HMACs K to get auth string
token = HMAC(K, salt, sha256).digest()

# authentication is successful, as the client knows the password
if token == HMAC(K, salt, sha256).digest():
    print('Authentication successful')
else:
    print('Authentication failed (wrong password?')

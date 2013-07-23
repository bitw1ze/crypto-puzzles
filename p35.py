#!/usr/bin/env python3.2

from hashlib import sha1
from sys import exit
from base64 import b16encode, b16decode
import os

from mycrypto import aes_cbc_encrypt, aes_cbc_decrypt, InvalidPadding


prime = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
generator = 2
  
class Node:

    def __init__(self, prime, generator):

        self.prime = prime
        self.generator = generator
        self.privkey, self.pubkey = self.generate_keypair()
        self.symkey = None

    def generate_keypair(self):

        privkey = int(str(b16encode(os.urandom(72)), 'utf8'), 16)
        pubkey = pow(self.generator, privkey, self.prime)
        return privkey, pubkey

    def negotiate_secret(self, peer_pubkey):

        self.peer_pubkey = peer_pubkey
        return pow(self.peer_pubkey, self.privkey, self.prime)

    def negotiate_key(self, peer_pubkey=None, secret=None):

        if secret is None:
            secret = self.negotiate_secret(peer_pubkey)

        _secret = bytes("%x" % secret, 'utf8')
        if len(_secret) % 2 != 0:
            _secret = b'0' + _secret
        self.symkey = sha1(_secret).digest()[:16]

        return self.symkey

def break_dh_g1():

    # Mallory intercepts the group negotiation and sets g=1
    alice = Node(prime, 1)
    mallory = Node(prime, 1)
    bob = Node(prime, 1)
    
    # Mallory doesn't tamper with the public keys
    alice_symkey = alice.negotiate_key(peer_pubkey=bob.pubkey)
    bob_symkey = alice.negotiate_key(peer_pubkey=alice.pubkey)

    # Alice encrypts a message with her symmetric key
    message = b"alice: hey, if you type in your pw, it will show as stars.\nalice: ********* see!"
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(message, alice_symkey, iv)

    # Mallory intercepts the message. He knows the secret is 1, so he
    # calculates the key and decrypts the message.
    mallory_symkey = mallory.negotiate_key(secret=1)
    plaintext = aes_cbc_decrypt(ciphertext, mallory_symkey, iv)

    return str(plaintext, 'utf8')

def break_dh_gp():

    # Mallory intercepts the group negotiation and sets g=1
    alice = Node(prime, prime)
    mallory = Node(prime, prime)
    bob = Node(prime, prime)
    
    # Mallory doesn't tamper with the public keys
    alice_symkey = alice.negotiate_key(peer_pubkey=bob.pubkey)
    bob_symkey = alice.negotiate_key(peer_pubkey=alice.pubkey)

    # Bob encrypts a message with his symmetric key
    message = b"bob: hunter2.\nbob: doesnt look like stars to me"
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(message, bob_symkey, iv)

    # Mallory intercepts the message. He knows the secret is 0, so he
    # calculates the key and decrypts the message.
    mallory_symkey = mallory.negotiate_key(secret=0)
    plaintext = aes_cbc_decrypt(ciphertext, mallory_symkey, iv)

    return str(plaintext, 'utf8')

def break_dh_gps1():

    # Mallory intercepts the group negotiation and sets g=1
    alice = Node(prime, prime-1)
    mallory = Node(prime, prime-1)
    bob = Node(prime, prime-1)
    
    # Mallory doesn't tamper with the public keys
    alice_symkey = alice.negotiate_key(peer_pubkey=bob.pubkey)
    bob_symkey = alice.negotiate_key(peer_pubkey=alice.pubkey)

    # Alice encrypts a message with her symmetric key
    message = b"alice: *******\nalice: thats what I see"
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(message, alice_symkey, iv)

    # Mallory intercepts the message. He knows the secret is either 1 or p-1,
    # so he calculates both keys and finds out which one can decrypt the
    # message.
    mallory_symkey = mallory.negotiate_key(secret=1)
    try:
        plaintext = aes_cbc_decrypt(ciphertext, mallory_symkey, iv)
    except InvalidPadding:
        mallory_symkey = mallory.negotiate_key(secret=prime-1)
        plaintext = aes_cbc_decrypt(ciphertext, mallory_symkey, iv)

    return str(plaintext, 'utf8')

def main():

    print("[+] Breaking DHE with negotiated groups where g=1, g=p, and g=p-1")
    print("[+] g=1")
    print(break_dh_g1())
    print("[+] g=p")
    print(break_dh_gp())
    print("[+] g=p-1")
    print(break_dh_gps1())

if __name__ == '__main__':
    exit(main())
        

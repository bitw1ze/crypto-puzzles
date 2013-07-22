from hashlib import sha1
from sys import exit
from base64 import b16encode, b16decode
import os

from mycrypto import aes_cbc_encrypt, aes_cbc_decrypt


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


def main():

    # Alice wants to encrypt a top-secret cookie recipe to Bob. They decide to
    # negotiate a symmetric encryption key using the Diffie-Hellman Key Exchange.
    alice = Node(prime, generator)

    # Alice sends her public key to Bob. Bob calculates the symmetric key from
    # Alice's public key. But wait, Mallory is on the network and replaced her
    # public key with her prime number! D:
    mallory = Node(prime, generator)
    bob = Node(alice.prime, mallory.generator)
    bob_symkey = bob.negotiate_key(peer_pubkey=mallory.prime)

    # Bob sends his public key to Alice, and Mallory does the same thing.
    alice_symkey = alice.negotiate_key(peer_pubkey=mallory.prime)

    # Alice encrypts the message
    recipe = b'6 eggs\n2 cups flower\n1 cup brown sugar\n1 tbsp vanilla ice'
    iv = os.urandom(16)
    ciphertext = aes_cbc_encrypt(recipe, alice_symkey, iv)

    # Mallory knows the secret value because p ** n % p = 0, and from it can
    # calculate the key.
    mallory_symkey = mallory.negotiate_key(secret=0)

    # Mallory intercepts and then decrypts the ciphertext
    plaintext = aes_cbc_decrypt(ciphertext, mallory_symkey, iv)
    print("Succesfully MITM'd the DH key exchange! Plaintext:")
    print(str(plaintext, 'utf8'))


if __name__ == '__main__':
    exit(main())
        

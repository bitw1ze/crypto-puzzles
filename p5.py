#!/usr/bin/python3.3

from base64 import b16encode
from itertools import cycle
import sys

def xor_repeat_cipher(msg, key):
  return bytearray([m ^ k for m, k in zip(msg, cycle(key))])

def main():
  plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
  key = b"ICE"
  ciphertext = xor_repeat_cipher(plaintext, key)
  print(b16encode(ciphertext).decode("utf8"))

if __name__ == '__main__':
  sys.exit(main())

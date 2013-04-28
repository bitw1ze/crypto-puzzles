#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

from base64 import b16encode
from itertools import cycle
from cryptlib import xor_repeat_cipher
import sys

def main():
  plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
  key = b"ICE"
  ciphertext = xor_repeat_cipher(plaintext, key)
  print(b16encode(ciphertext).decode("utf8"))

if __name__ == '__main__':
  sys.exit(main())

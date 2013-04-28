#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

from base64 import b16encode, b16decode
from cryptlib import fixed_xor
import sys

def main():
  msg1 = b16decode(b'1c0111001f010100061a024b53535009181c', casefold=True)
  msg2 = b16decode(b'686974207468652062756c6c277320657965', casefold=True)
  print(b16encode(fixed_xor(msg1, msg2)).decode("utf8"))

if __name__ == '__main__':
  sys.exit(main())

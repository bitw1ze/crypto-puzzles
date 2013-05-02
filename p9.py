#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

""" I defined my padding functions in mycrypto.py """

from base64 import b16encode
from mycrypto import pkcs7_pad, pkcs7_unpad
import sys

def main():
  padded_submarine = pkcs7_pad(b"YELLOW SUBMARINE", 20)
  print(b16encode(padded_submarine).decode('utf8'))
  unpadded_submarine = pkcs7_unpad(padded_submarine, 20)
  print(unpadded_submarine.decode("utf8"))
# print out some more values to make sure it works
  for i in range(18):
    print(b16encode(pkcs7_pad(('A'*i).encode('utf8'), 16)).decode('utf8'))

if __name__ == '__main__':
  sys.exit(main())

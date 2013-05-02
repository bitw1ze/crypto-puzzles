#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

""" I defined my padding functions in mycrypto.py """

from mycrypto import pkcs7_pad, pkcs7_unpad
import sys

def main():
  block_size = 16
  try:
    print(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", block_size))
    print(pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", block_size))
  except Exception as e:
    print(e)

if __name__ == '__main__':
  sys.exit(main())

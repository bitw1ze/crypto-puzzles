#!/usr/bin/python3.3

import sys, base64
from sys import exit
from base64 import b64encode, b16decode

def h2b64(msg):
  return base64.b64encode(base64.b16decode(msg, casefold=True))
  

def main():
  msg = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  
  print(h2b64(msg).decode('utf8'))

if __name__ == "__main__":
  sys.exit(main())

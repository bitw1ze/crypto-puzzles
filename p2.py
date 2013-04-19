#!/usr/bin/python3.3

from base64 import b16encode, b16decode
from sys import exit

def fixed_xor(msg1, msg2):
  if len(msg1) != len(msg2):
    raise Exception("Buffers are not same size!")

  return bytearray([a ^ b for (a,b) in zip(msg1, msg2) ])

def main():
  msg1 = b16decode(b'1c0111001f010100061a024b53535009181c', casefold=True)
  msg2 = b16decode(b'686974207468652062756c6c277320657965', casefold=True)
  print(b16encode(fixed_xor(msg1, msg2)).decode("utf8"))

if __name__ == '__main__':
  exit(main())

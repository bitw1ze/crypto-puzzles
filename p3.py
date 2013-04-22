#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""
+=====================+
|       ANSWER        |
+=====================+

Key: 0x58
Plaintext: Cooking MC's like a pound of bacon

"""

from base64 import b16decode, b16encode
import string, sys

def xor_byte_bruteforce(ct):
  plaintext, score, key = None, 0, 0
  for k in range(0, 256):
    pt, sc = xor_byte_decrypt_and_score(ct, k)
    if sc > score:
      plaintext, score, key = pt, sc, k

  return plaintext, score, key

def xor_byte_crypt(msg, key):
  return bytearray([m ^ key for m in msg])

def xor_byte_decrypt_and_score(ct, key):
  pt = xor_byte_crypt(ct, key)
  return pt, calc_score(pt)

def calc_score(pt):
  score = 0
  charpoints = {'e':12, 't':9, 'a':8, 'o':8, 'i':7, 'n':7, 's':6, 'h':6, 'r':6, 'd':4, 'u':4}

  for x in pt:
    x = chr(x)
    if x not in string.printable:
      score -= 10
    elif x == ' ':
      score += 13
    elif x in charpoints.keys():
      score += charpoints[x]
    elif x in string.ascii_lowercase:
      score += 3
    elif x in string.ascii_uppercase:
      score += 2

  return score

def main():
  ciphertext = b16decode(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', casefold=True)
  plaintext, _, key = xor_byte_bruteforce(ciphertext)
  print("Key: 0x%s" % b16encode(bytearray([key])).decode("utf8"))
  print("Plaintext:", plaintext.decode('utf8'))

if __name__ == '__main__':
  sys.exit(main())

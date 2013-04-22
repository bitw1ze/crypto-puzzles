#!/usr/bin/python3.3

from base64 import b16decode
import string, sys

def xor_byte_bruteforce(ct):
  plaintext, score = None, 0
  for key in range(0, 256):
    pt, sc = xor_byte_decrypt_and_score(ct, key)
    if sc > score:
      plaintext, score = pt, sc

  return plaintext, score

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
  plaintext, _ = xor_byte_bruteforce(ciphertext)
  print(plaintext.decode('utf8'))

if __name__ == '__main__':
  sys.exit(main())

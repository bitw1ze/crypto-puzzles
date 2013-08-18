_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""

This module contains helper functions I implemented that are commonly used in
the challenges.

"""

from functools import reduce
from base64 import b16encode, b16decode

def chunks(s, n):
  return [bytes(s[i:i+n]) for i in range(0, len(s), n)]

def flatten(lst):
  return bytes([]) if not lst else bytes(reduce(lambda a,b: a+b, lst))

def identity(*args):
  return args[0]

def b2i(data):

    _ = str(b16encode(data), 'utf8')
    if len(_) % 2 is not 0:
        _ = '0' + _
    return int(_, 16)

def i2b(data):

    x = hex(data)[2:]
    if len(x) % 2 != 0:
        x = '0' + x
    x = bytes(x, 'utf8')
    return b16decode(x, True)

def i2s(data):

    return str(i2b(data), 'utf8')

def b2u(data):

    return str(data, 'utf8')

def u2b(data):

    return bytes(data, 'utf8')

def b2hs(data):

    x = b2u(b16encode(data))
    if len(x) % 2 != 0:
        x = '0' + x
    return x

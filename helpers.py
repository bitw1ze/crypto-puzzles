_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

"""

This module contains helper functions I implemented that are commonly used in
the challenges.

"""

from functools import reduce
from base64 import b16encode, b16decode

def chunks(s, n):
    ''' split bytes s into chunks of size n '''

    return [bytes(s[i:i+n]) for i in range(0, len(s), n)]

def flatten(lst):
    ''' flatten an list of list of bytes into a single list of bytes '''

    return bytes([]) if not lst else bytes(reduce(lambda a,b: a+b, lst))

def identity(*args):
    ''' simply return the first argument '''

    return args[0]

def b2i(data):
    ''' convert bytes to integer '''

    _ = str(b16encode(data), 'utf8')
    if len(_) % 2 is not 0:
        _ = '0' + _
    return int(_, 16)

def i2b(data):
    ''' convert integer to bytes '''

    x = hex(data)[2:]
    if len(x) % 2 != 0:
        x = '0' + x
    x = bytes(x, 'utf8')
    return b16decode(x, True)

def i2s(data):
    ''' convert integer to string '''

    return str(i2b(data), 'utf8')

def s2i(data):
    ''' string to integer '''

    return b2i(u2b(data))


def b2s(data):
    ''' convert binary to unicode string '''

    return str(data, 'utf8')

def s2b(data):
    ''' convert unicode string to binary '''

    return bytes(data, 'utf8')

def b2hs(data):
    ''' convert binary to hex string '''

    x = b2s(b16encode(data))
    if len(x) % 2 != 0:
        x = '0' + x
    return x

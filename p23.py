#!/usr/bin/env python3.2

_author_ = "Gabe Pike"
_email_ = "gpike@isecpartners.com"

from sys import exit
from time import time
from operator import lshift, rshift
from myrand import MT19937

def temper(y):
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= (y >> 18)
    return y

def untemper(y):
    y = _untemper(y, 18, rshift)
    y = _untemper(y, 15, lshift, 0xefc60000)
    y = _untemper(y, 7, lshift, 0x9d2c5680)
    y = _untemper(y, 11, rshift)

    return y

def _untemper(y, shiftn, shiftf, magic=0xFFFFFFFF):
    ''' a somewhat generic untempering function for MT19937 output

    y       --  value you want to reverse 
    shiftn  --  number of bits to shift.
    shiftf  --  shift function (right or left); defined as a function of two
                arguments, where arg1 is the value to shift and arg2 is the
                number of bits to shift.
    magic   --  magic value to AND with. If not specified it will have no
                effect.
    
    '''
    result = y
    tmp = None
    for i in range(32//shiftn+1):
        tmp = shiftf(result, shiftn)
        result = y ^ (tmp & magic) 
    return result

def reverse_rng(rng):
    untempered = [untemper(rng.rand()) for i in range(624)]
    return MT19937(state=untempered)

def main():
    target_rng = MT19937(int(time()))
    reverse_rng(target_rng)
    reversed_rng = reverse_rng(target_rng)
    print("Next value of target RNG: %d" % target_rng.rand())
    print("Next value of reversed RNG: %d" % reversed_rng.rand())

if __name__ == '__main__':
    exit(main())

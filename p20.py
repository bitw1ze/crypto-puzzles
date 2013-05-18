import string
from sys import exit
from base64 import b64decode
from functools import reduce
from mycrypto import aes_ctr_crypt, fixed_xor
from Crypto.Cipher import AES
from Crypto import Random

def calc_score(pt):
    ''' our good friend from problem 3 is back again! '''
    score = 0
    charpoints = {'e':12, 't':9, 'a':8, 'o':8, 'i':7, 'n':7, 's':6, 'h':6, 'r':6, 'd':4, 'u':4, 'T':9, 'I':8, 'R':8, 'S':8, 'M':8, 'L':8, 'Y':7}

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
        else:
            score += 1
    return score

def break_fail_ctr(cts):
    shortest = reduce(lambda acc, x: min(acc, len(x)), cts, len(cts[0]))
    keystream = b''

    for i in range(shortest):
        score = 0
        keybyte = 0
        for j in range(256):
            _candidate = [ct[i] ^ j for ct in cts]
            _score = calc_score(_candidate)
            if _score > score:
                keybyte = j
                score = _score
        keystream += bytes([keybyte])

    return [fixed_xor(keystream, ct[:shortest]) for ct in cts]
    # holy shit it worked

def main():
    ciphertexts = None
    with open('p20-input.txt') as fh:
        ciphertexts = [b64decode(pt.encode('utf8')) for pt in fh.readlines()]

    plaintexts = break_fail_ctr(ciphertexts)
    for pt in plaintexts:
        print(pt.decode('utf8'))

if __name__ == '__main__':
    exit(main())

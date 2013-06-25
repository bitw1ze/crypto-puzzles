#!/usr/bin/env python3

''' Forge a signature via SHA1 hash length extension attack

See thirdparty/sha1.py for modification of existing SHA1 implementation '''

import struct
from sys import exit
from base64 import b16encode
from random import randint
from Crypto import Random
from thirdparty.sha1 import sha1

key = None

def MAC(message, key):

    return sha1(key + message)

def authenticate(message, key, mac):

    return MAC(message, key) == mac

def blackbox_authenticate(message, mac):

    return authenticate(message, key, mac)

def sha1_pad(msg, prefix_len=0, key_len=0):
    
    length = len(msg) 
    one_pad = b"\x80"
    zero_pad = b"\x00" * (55 - key_len - (length % 64))
    len_pad = struct.pack('>Q', (length+prefix_len+key_len)*8)

    return msg + one_pad + zero_pad + len_pad

def hash_length_extension(prefix, mac, injection, key_len):

    prefix_len = 64 * ((len(prefix) + key_len) // 64) + 64
    padded_prefix = sha1_pad(prefix, key_len=key_len)
    padded_injection = sha1_pad(injection, prefix_len=prefix_len)

    forged_message = padded_prefix + injection
    forged_mac = sha1(message=padded_injection, seed=mac, pad=False)
    return forged_message, forged_mac

def main():

    global key

    key = Random.new().read(randint(1, 32))
    message = b'crypto=hard;pimping=easy'
    injection = b';admin=true'
    mac = MAC(message, key)

    print("Key:     %s" % key)
    print("Message: %s " % str(message, 'utf8'))
    print("MAC:     %s" % str(b16encode(mac).lower(), 'utf8'))
    print()

    # guess the key length
    for i in range(1, 32+1):
        fmsg, fmac = hash_length_extension(message, mac, injection, key_len=i)
        if blackbox_authenticate(fmsg, fmac):
            break

    print("Key length:     %d " % i)
    print("Forged message: %s " % fmsg)
    print("Forged MAC:     %s " % str(b16encode(fmac).lower(), 'utf8'))
    print()

    if blackbox_authenticate(fmsg, fmac):
        print("Authenticated the message")
    else:
        print("Failed to authenticate the message")

if __name__ == '__main__':
    exit(main())

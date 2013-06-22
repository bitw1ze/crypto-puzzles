import struct
from sys import exit
from thirdparty.sha1 import sha1
from base64 import b16encode

def MAC(message, key):
    return sha1(key + message)

def authenticate(message, key, mac):
    return MAC(message, key) == mac

def sha1_pad(msg, prefix_len=0, key_len=0):
    
    length = len(msg) 
    one_pad = b"\x80"
    zero_pad = b"\x00" * (55 - key_len - (length % 64))
    len_pad = struct.pack('>Q', (length+prefix_len+key_len)*8)
    #print(key_len, prefix_len)
    #print(length, len(one_pad), len(zero_pad), len(len_pad))

    return msg + one_pad + zero_pad + len_pad

def hash_length_extension(prefix, mac, injection, key_len):

    prefix_len = 64 * ((len(prefix) + key_len) // 64) + 64
    padded_prefix = sha1_pad(prefix, key_len=key_len)
    padded_injection = sha1_pad(injection, prefix_len=prefix_len)

    forged_message = padded_prefix + injection
    forged_mac = sha1(message=padded_injection, seed=mac)
    return forged_message, forged_mac

def main():
    message = b'crypto=hard;pimping=easy'
    key = b'123456'
    message = b'from=123&to=456&amount=50'
    injection = b';admin=true'
    key = b's3cRe7-#!@~'
    mac = MAC(message, key)
    injection = b'&to=666&amount=99999'

    print("Key:     %s" % key)
    print()
    print("Message: %s " % str(message, 'utf8'))
    print("MAC:     %s" % str(b16encode(mac).lower(), 'utf8'))
    print()

    forged_message, forged_mac = (
            hash_length_extension(message, mac, injection, len(key)))

    print("Forged message: %s " % forged_message)
    print("Forged MAC:     %s " % str(b16encode(forged_mac).lower(), 'utf8'))
    print()

    if authenticate(forged_message, key, forged_mac):
        print("Authenticated the message")
    else:
        print("Failed to authenticate the message")

if __name__ == '__main__':
    exit(main())

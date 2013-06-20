import struct
from sys import exit
from slowsha import sha1, SHA1

def MAC(message, key):
    return sha1(key + message).digest()

def authenticate(message, key, mac):
    return MAC(message, key) == mac

def validate_message(message, key, mac):
    print('message: %s is %s' % (message, 
          "valid" if authenticate(message,key,mac) else "invalid"))

def sha1_pad(msg, prefix_len=0, key_len=0):
    
    length = len(msg) 
    one_pad = b"\x80"
    zero_pad = b"\x00" * (55 - key_len - (length % 64))
    len_pad = struct.pack('>Q', (length+prefix_len+key_len)*8)
    #print(key_len, prefix_len)
    #print(length, len(one_pad), len(zero_pad), len(len_pad))

    return msg + one_pad + zero_pad + len_pad

def hash_length_extension(prefix, mac, injection, key_len):
    print(mac)

    prefix_len = 64 * ((len(prefix) + key_len) // 64) + 64
    padded_prefix = sha1_pad(prefix, key_len=key_len)
    padded_injection = sha1_pad(injection, prefix_len=prefix_len)

    forged_message = padded_prefix + injection
    forged_mac = SHA1(message=padded_injection, seed=mac).digest()
    print(padded_injection)
    print(forged_mac)
    return forged_message, forged_mac

def main():
    message = b'crypto=hard;pimping=easy'
    key = b'123456'
    message = b'from=123&to=456&amount=50'
    injection = b';admin=true'
    key = b's3cRe7-#!@~'
    mac = MAC(message, key)
    injection = b'&to=666&amount=99999'

    forged_message, forged_mac = (
            hash_length_extension(message, mac, injection, len(key)))
    validate_message(forged_message, key, forged_mac)

if __name__ == '__main__':
    exit(main())

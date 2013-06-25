#!/usr/bin/env python3

''' Attack insecure compare of SHA1-HMAC with a large delay between compares

This program guesses each byte of the HMAC by observing time differences. To
test it, first run the web server in one window. Then run the client.

./p31-server.py
./p31-client.py
'''

import sys
from base64 import b16encode
from time import time

import requests

from p31 import *

proto = 'http'
path = 'verify'
url = '%s://%s:%d/%s' % (proto, host, port, path)

def main():

    # signature for this message: 434D11195A10D3DF19B0FCEBC6C0C147E3BC5FFA
    message = 'foobar'
    signature = bytearray(b'\x00'*20)

    for i in range(20):
        for j in range(256):
            signature[i] = j
            params = '/%s/%s' % (message, str(b16encode(signature), 'utf8'))

            begin = time()
            requests.get(url+params)
            elapsed = time() - begin
            if elapsed >= (i+1)*latency:
                signature[i] = j
                print("%x" % j, end='')
                sys.stdout.flush()
                break

    print()
    response = requests.get(url)
    if response.status_code == 200:
        print("Success!")
        print(str(b16encode(signature), 'utf8'))
    else:
        print("Failure!")

if __name__ == '__main__':
    sys.exit(main())

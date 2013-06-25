#!/usr/bin/env python3

''' Attack insecure compare of SHA1-HMAC with a small delay between compares

This program guesses the HMAC by collecting statistics on each byte, one at a
time. The byte value that takes the longest to return is selected.  test it,
first run the web server in one window. Then run the client.

Requires the "requests" HTTP module to run
'''

import sys
from base64 import b16encode
from time import time

import requests

from p32server import host, port, latency

proto = 'http'
path = 'verify'
url = '%s://%s:%d/%s' % (proto, host, port, path)

def main():

    # signature for this message: 434D11195A10D3DF19B0FCEBC6C0C147E3BC5FFA
    message = 'foobar'
    signature = bytearray(b'\x00'*20)

    for i in range(20):

        times = []
        for j in range(256):
            signature[i] = j
            params = '/%s/%s' % (message, str(b16encode(signature), 'utf8'))

            total = 0
            attempts = 13
            for k in range(attempts):
                begin = time()
                requests.get(url+params)
                elapsed = time() - begin
                total += elapsed
            times.append(total)

        signature[i] = times.index(max(times))
        print("%.2x" % signature[i], end='')
        sys.stdout.flush()

    print()
    params = '/%s/%s' % (message, str(b16encode(signature), 'utf8'))
    response = requests.get(url+params)
    if response.status_code == 200:
        print("Success!")
        print(str(b16encode(signature), 'utf8'))
    else:
        print("Failure!")

if __name__ == '__main__':
    sys.exit(main())

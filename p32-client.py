import sys
from base64 import b16encode
from time import time

import requests

from p32 import *


proto = 'http'
path = 'verify'
url = '%s://%s:%d/%s' % (proto, host, port, path)

def main():

    message = 'foobar'
    signature = bytearray(b'\x00'*20)

    for i in range(20):

        times = []
        for j in range(256):
            signature[i] = j
            params = '/%s/%s' % (message, str(b16encode(signature), 'utf8'))

            total = 0
            for k in range(10):
                begin = time()
                requests.get(url+params)
                elapsed = time() - begin
                total += elapsed
            times.append(total)

        signature[i] = times.index(max(times))
        print("%.2x" % signature[i], end='')
        sys.stdout.flush()

    print()
    response = requests.get(url)
    if response.status_code == 200:
        print("Success!")
        print(str(b16encode(signature), 'utf8'))
    else:
        print("Failure!")

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3

''' Runs a web server with a compares a SHA1-HMAC insecurely 

See p32-client.py for more information '''

from sys import exit
from hashlib import sha1
from base64 import b16decode, b16encode

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.httpexceptions import HTTPInternalServerError

from mycrypto import sha1_hmac
from time import sleep
from p32 import *

key = b'123456'

def verify_signature(request):

    params = request.matchdict
    message = bytes(params['msg'], 'utf8')
    signature = b16decode(bytes(params['sig'], 'utf8'), casefold=True)
    verifier = sha1_hmac(key, message).digest()
    result = insecure_compare(verifier, signature)
    if result:
        return Response("Success")
    else:
        raise HTTPInternalServerError()

def insecure_compare(str1, str2):

    if len(str1) != len(str2):
        return False

    for c1, c2 in zip(str1, str2):
        if c1 != c2:
            return False
        sleep(latency)
    else:
        return True

def main():

    config = Configurator()
    config.add_route('verify', '/verify/{msg}/{sig}')
    config.add_view(verify_signature, route_name='verify')
    app = config.make_wsgi_app()
    server = make_server(host, port, app)
    server.serve_forever()

if __name__ == '__main__':
    exit(main())

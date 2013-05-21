from sys import exit
from slowsha import sha1

def MAC(message, key):
    return sha1(key + message).digest()

def authenticate(message, key, mac):
    return MAC(message, key) == mac

def validate_message(message, key, mac):
    print('message: "%s" (%s)' % (message.decode('utf8'), 
          "valid" if authenticate(message,key,mac) else "invalid"))

def main():
    key = b'123456'
    message = b'no one can break this crypto because i am an OG'
    mac = MAC(message, key)

    validate_message(message, key, mac)
    validate_message(message[:-1]+b'J', key, mac)
    validate_message(message, key+b'7', mac)

if __name__ == '__main__':
    exit(main())

from base64 import b16encode
import sys

def pkcs7_pad(pt, blocksize):
  padlen = blocksize - len(pt) % blocksize
  return bytearray(pt) + bytearray([padlen]*padlen)

# might as well implement this too
def pkcs7_unpad(ct, blocksize):
  padlen = ct[-1]
  if padlen > blocksize or not all((lambda x: x == padlen, ct[-padlen:])):
    raise Exception("Invalid padding! I sure hope you MAC'd already...")

  return ct[:-padlen]

def main():
  padded_submarine = pkcs7_pad(b"YELLOW SUBMARINE", 20)
  print(b16encode(padded_submarine).decode('utf8'))
  unpadded_submarine = pkcs7_unpad(padded_submarine, 20)
  print(unpadded_submarine.decode("utf8"))
# print out some more values to make sure it works
  for i in range(18):
    print(b16encode(pkcs7_pad(('A'*i).encode('utf8'), 16)).decode('utf8'))

if __name__ == '__main__':
  sys.exit(main())

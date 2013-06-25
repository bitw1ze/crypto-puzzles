"""  Cryptochallenge note: This MD4 implementation was a pain in the ass to
     modify for this challenge, but it was better than the alternatives. I
     ended up making the MD4 code a lot cleaner, but I would like to completely
     get rid of the U32 class. There is no point in using it, as the struct
     module does everything you need. """

#    md4.py implements md4 hash class for Python
#    Version 1.0
#    Copyright (C) 2001-2002  Dmitry Rozmanov
#
#    based on md4.c from "the Python Cryptography Toolkit, version 1.0.0
#    Copyright (C) 1995, A.M. Kuchling"
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#    e-mail: dima@xenon.spb.ru
#
#====================================================================

# MD4 validation data

md4_test= [
      (b'', b'31D6CFE0D16AE931B73C59D7E0C089C0'),
      (b"a",   b'BDE52CB31DE33E46245E05FBDBD6FB24'),
      (b"abc",   b'A448017AAF21D8525FC10AE87AA6729D'),
      (b"message digest",   b'D9130A8164549FE818874806E1C7014B'),
      (b"abcdefghijklmnopqrstuvwxyz",   b'D79E1C308AA5BBCDEEA8ED63DF412DA9'),
      (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
       b'043F8582F241DB351CE627E153E7F0E4'),
      (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      b'E33B4DDC9C38F2199C3E7B164FCC0536'),
     ]

#====================================================================
import struct
from base64 import b16encode
from .U32 import U32

#--------------------------------------------------------------------
class MD4:
    A = None
    B = None
    C = None
    D = None
    count, len1, len2 = None, None, None
    buf = []

    #-----------------------------------------------------
    def __init__(self, message, seed=None, pad=True):

        self.pad = pad
        self.message = message
        if not seed:
            self.A = U32(0x67452301)
            self.B = U32(0xefcdab89)
            self.C = U32(0x98badcfe)
            self.D = U32(0x10325476)
        else:
            seed = map(U32, struct.unpack('<4I', seed))
            self.A, self.B, self.C, self.D = seed
        vals = (self.A, self.B, self.C, self.D)

        self.count, self.len1, self.len2 = U32(0), U32(0), U32(0)
        self.buf = [0x00] * 64
        self.update(message)

    #-----------------------------------------------------
    def __repr__(self):
        r = 'A = %s, \nB = %s, \nC = %s, \nD = %s.\n' % (self.A.__repr__(), self.B.__repr__(), self.C.__repr__(), self.D.__repr__())
        r = r + 'count = %s, \nlen1 = %s, \nlen2 = %s.\n' % (self.count.__repr__(), self.len1.__repr__(), self.len2.__repr__())
        for i in range(4):
            for j in range(16):
                r = r + '%4s ' % hex(self.buf[i+j])
            r = r + '\n'

        return r
    #-----------------------------------------------------
    def make_copy(self):

        dest = new(self.message)

        dest.len1 = self.len1
        dest.len2 = self.len2
        dest.A = self.A
        dest.B = self.B
        dest.C = self.C
        dest.D = self.D
        dest.count = self.count
        for i in range(self.count):
            dest.buf[i] = self.buf[i]

        return dest

    #-----------------------------------------------------
    def update(self, str):

        buf = []
        for i in str: buf.append(i)
        ilen = U32(len(buf))

        # check if the first length is out of range
        # as the length is measured in bits then multiplay it by 8
        if (int(self.len1 + (ilen << 3)) < int(self.len1)):
            self.len2 = self.len2 + U32(1)

        self.len1 = self.len1 + (ilen << 3)
        self.len2 = self.len2 + (ilen >> 29)

        L = U32(0)
        bufpos = 0
        while (int(ilen) > 0):
            if (64 - int(self.count)) < int(ilen): 
                L = U32(64 - int(self.count))
            else: 
                L = ilen

            for i in range(int(L)): 
                self.buf[i + int(self.count)] = buf[i + bufpos]
            self.count = self.count + L
            ilen = ilen - L
            bufpos = bufpos + int(L)

            if (int(self.count) == 64):
                self.count = U32(0)
                X = []
                i = 0
                for j in range(16):
                    X.append(U32(self.buf[i]) + (U32(self.buf[i+1]) << 8)  + \
                    (U32(self.buf[i+2]) << 16) + (U32(self.buf[i+3]) << 24))
                    i = i + 4

                A = self.A
                B = self.B
                C = self.C
                D = self.D

                A = f1(A,B,C,D, 0, 3, X)
                D = f1(D,A,B,C, 1, 7, X)
                C = f1(C,D,A,B, 2,11, X)
                B = f1(B,C,D,A, 3,19, X)
                A = f1(A,B,C,D, 4, 3, X)
                D = f1(D,A,B,C, 5, 7, X)
                C = f1(C,D,A,B, 6,11, X)
                B = f1(B,C,D,A, 7,19, X)
                A = f1(A,B,C,D, 8, 3, X)
                D = f1(D,A,B,C, 9, 7, X)
                C = f1(C,D,A,B,10,11, X)
                B = f1(B,C,D,A,11,19, X)
                A = f1(A,B,C,D,12, 3, X)
                D = f1(D,A,B,C,13, 7, X)
                C = f1(C,D,A,B,14,11, X)
                B = f1(B,C,D,A,15,19, X)

                A = f2(A,B,C,D, 0, 3, X)
                D = f2(D,A,B,C, 4, 5, X)
                C = f2(C,D,A,B, 8, 9, X)
                B = f2(B,C,D,A,12,13, X)
                A = f2(A,B,C,D, 1, 3, X)
                D = f2(D,A,B,C, 5, 5, X)
                C = f2(C,D,A,B, 9, 9, X)
                B = f2(B,C,D,A,13,13, X)
                A = f2(A,B,C,D, 2, 3, X)
                D = f2(D,A,B,C, 6, 5, X)
                C = f2(C,D,A,B,10, 9, X)
                B = f2(B,C,D,A,14,13, X)
                A = f2(A,B,C,D, 3, 3, X)
                D = f2(D,A,B,C, 7, 5, X)
                C = f2(C,D,A,B,11, 9, X)
                B = f2(B,C,D,A,15,13, X)

                A = f3(A,B,C,D, 0, 3, X)
                D = f3(D,A,B,C, 8, 9, X)
                C = f3(C,D,A,B, 4,11, X)
                B = f3(B,C,D,A,12,15, X)
                A = f3(A,B,C,D, 2, 3, X)
                D = f3(D,A,B,C,10, 9, X)
                C = f3(C,D,A,B, 6,11, X)
                B = f3(B,C,D,A,14,15, X)
                A = f3(A,B,C,D, 1, 3, X)
                D = f3(D,A,B,C, 9, 9, X)
                C = f3(C,D,A,B, 5,11, X)
                B = f3(B,C,D,A,13,15, X)
                A = f3(A,B,C,D, 3, 3, X)
                D = f3(D,A,B,C,11, 9, X)
                C = f3(C,D,A,B, 7,11, X)
                B = f3(B,C,D,A,15,15, X)

                self.A = self.A + A
                self.B = self.B + B
                self.C = self.C + C
                self.D = self.D + D

    #-----------------------------------------------------
    def digest(self):

        if self.pad:
            padding = bytearray(b'\x00' * 60)
            padding[0] = 0x80
            padlen, oldlen1, oldlen2 = U32(0), U32(0), U32(0)


            oldlen1 = self.len1
            oldlen2 = self.len2
            if (56 <= int(self.count)): 
                padlen = U32(56 - int(self.count) + 64)
            else: 
                padlen = U32(56 - int(self.count))

            pad_len = struct.pack('<2I', oldlen1, oldlen2)

            padding = int_array2str(padding[:int(padlen)] + pad_len)
            self.update(padding)
            res = self
        else:
            res = self

        vals = map(int, [res.A, res.B, res.C, res.D])
        return int_array2str(struct.pack('<4I', *vals))

#====================================================================
# helpers
def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))
def G(x, y, z): return (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
def H(x, y, z): return ((x) ^ (y) ^ (z))

def ROL(x, n): return (((x) << n) | ((x) >> (32-n)))

def f1(a, b, c, d, k, s, X): return ROL(a + F(b, c, d) + X[k], s)
def f2(a, b, c, d, k, s, X): return ROL(a + G(b, c, d) + X[k] + U32(0x5a827999), s)
def f3(a, b, c, d, k, s, X): return ROL(a + H(b, c, d) + X[k] + U32(0x6ed9eba1), s)

#--------------------------------------------------------------------
# helper function
def int_array2str(array):
        return bytes(array)
        str = b''
        for i in array:
            str = str + chr(i)
        return str

#--------------------------------------------------------------------
# To be able to use md4.new() instead of md4.MD4()
new = MD4

class MT19937:


    def __init__(self, seed=None, state=None):
        self.index = 0
        if not state:
            if not seed:
                from time import time
                seed = int(time())
            self.MT = [0]*624
            self.MT[0] = seed
            for i in range(1, 623+1):
                self.MT[i] = 0x6c078965 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i
                self.MT[i] &= 0xFFFFFFFF 
        else:
            self.MT = state

    def rand(self):
        if self.index == 0:
            self.__generate_state()

        y = self.MT[self.index]
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)
        
        self.index = (self.index + 1) % 624
        return y

    def read(self, nbytes):
        output = []
        rng_out = None
        for i in range(nbytes):
            slot = i % 4
            if slot == 0:
                tmprand = self.rand()
            output.append((tmprand >> (slot * 8)) & 0xFF)
        return bytes(output)
 
    def __generate_state(self):
        for i in range(623+1):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.MT[i] ^= 0x9908b0df

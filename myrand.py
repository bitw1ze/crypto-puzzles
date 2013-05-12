class MT19937:


    MT = [0]*624
    index = 0

    def __init__(self, seed):
        self.MT[0] = seed
        for i in range(1, 623+1):
            self.MT[i] = (0xFFFFFFFF & ((0x6c078965 * (self.MT[i-1] ^
                         (self.MT[i-1] >> 30)))+i))

    def rand(self):
        if self.index == 0:
            self.__generate()

        y = self.MT[self.index]
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)
        
        self.index = (self.index + 1) % 624
        return y

    def __generate(self):
        for i in range(623+1):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] & 0x7fffffff)
            self.MT[i] = self.MT[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.MT[i] ^= 0x9908b0df

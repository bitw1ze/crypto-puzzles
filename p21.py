from sys import exit
from time import time
from myrand import MT19937

def main():
    print("10 random ints seeded with 0")
    print("----------------------------")
    rand1 = MT19937(0)
    for i in range(0, 10):
        print(rand1.rand())

    print("10 random ints seeded with system time")
    print("----------------------------")
    rand2 = MT19937(int(time()))
    for i in range(0, 10):
        print(rand2.rand())

if __name__ == '__main__':
    exit(main())


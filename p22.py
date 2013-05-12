from time import time, sleep
from sys import exit
from myrand import MT19937

simulated_time = None

def delay(minsec=40, maxsec=1000):
    rng = MT19937(int(time()))
    return rng.rand() % (maxsec - minsec) + minsec

def super_secure_random(simulate=False):
    global simulated_time

    print("sleeping for random delay")
    if simulate:
        ts = int(time()) + delay()
        simulated_time = ts
    else:
        sleep(delay())
        ts = int(time())

    print("timestamp (secret seed): %d" % ts)
    rng = MT19937(ts)

    print("sleeping for random delay again")
    if simulate:
        simulated_time += delay()
    else:
        sleep(delay())

    return rng.rand()

def break_super_secure_random(simulate=False):
    result = super_secure_random(simulate)
    print("RNG output: %d" % result)
    timestamp = simulated_time if simulate else int(time())
    while timestamp != 0:
        rng = MT19937(timestamp)
        res = rng.rand()
        if res == result:
            return timestamp
        timestamp -= 1

    raise Exception("Your code is bad and you should feel bad")

def main():
    print("Found seed: %d" % break_super_secure_random(simulate=True))
    
if __name__ == '__main__':
    exit(main())

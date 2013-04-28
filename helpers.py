from functools import reduce

def chunks(s, n):
  return [s[i:i+n] for i in range(0, len(s), n)]

def flatten(lst):
  return [] if not lst else reduce(lambda a,b: a+b, lst)

def identity(*args):
  return args[0]

def fixed_xor(msg1, msg2):
  if len(msg1) != len(msg2):
    raise Exception("Buffers are not same size!")

  return bytearray([a ^ b for (a,b) in zip(msg1, msg2) ])



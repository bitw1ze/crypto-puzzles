from functools import reduce

def chunks(s, n):
  return [bytes(s[i:i+n]) for i in range(0, len(s), n)]

def flatten(lst):
  return bytes([]) if not lst else bytes(reduce(lambda a,b: a+b, lst))

def identity(*args):
  return args[0]

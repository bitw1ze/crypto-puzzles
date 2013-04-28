from functools import reduce

def chunks(s, n):
  return [s[i:i+n] for i in range(0, len(s), n)]

def flatten(lst):
  return [] if not lst else reduce(lambda a,b: a+b, lst)

def identity(*args):
  return args[0]

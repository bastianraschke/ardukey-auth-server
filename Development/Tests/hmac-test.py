#!/usr/bin/env python3

d = {}
d['a'] = 1
d['b'] = 2
d['c'] = 3


for key in sorted(d):
    print "%s: %s" % (key, d[key])


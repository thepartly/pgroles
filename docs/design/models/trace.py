#!/usr/bin/env python3
"""Condense a TLC counterexample: print each state's action and only the variables that changed.
Usage: python3 trace.py out/<cfg>.log [var,var,...to hide]"""
import re, sys
txt = open(sys.argv[1]).read()
hide = set(sys.argv[2].split(',')) if len(sys.argv) > 2 else set()
states = re.split(r'\nState (\d+): ', txt)
prev = {}
for i in range(1, len(states), 2):
    n, body = states[i], states[i+1]
    head, _, rest = body.partition('\n')
    rest = rest.split('\n\n')[0]
    cur = {}
    for m in re.finditer(r'^/\\ (\w+) = (.*?)(?=^/\\ |\Z)', rest, re.S | re.M):
        cur[m.group(1)] = ' '.join(m.group(2).split())
    act = re.sub(r' line.*', '', head).strip('<>')
    if 'Stuttering' in head or 'Back to state' in head:
        print(f'{n}: {head}'); continue
    print(f'{n}: {act}')
    for k, v in cur.items():
        if k in hide: continue
        if prev.get(k) != v:
            print(f'      {k} = {v}')
    prev = cur
m = re.search(r'Back to state.*', txt)

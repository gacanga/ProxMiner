#!/usr/bin/env python3
"""ProxMiner - checks gpu/fe_ptx.h without a GPU: a tiny interpreter of the PTX subset it uses
(mul/mad .lo/.hi with carry-in/out, add/sub with carry, and, mov), on random and edge operands,
against Python integers modulo p = 2^255 - 19 (results must also stay below 2^256)."""
import re, random, sys
M = 0xffffffff
P = 2**255 - 19

def parse(path):
    src = open(path).read()
    funcs = {}
    for m in re.finditer(r'void (fe_\w+_ptx)\(.*?\)\n\{\n\tasm\(\n(.*?)\n\t\t:', src, re.S):
        name, body = m.group(1), m.group(2)
        lines = [l.strip()[1:].replace('\\n\\t"', '').strip() for l in body.split('\n')]
        funcs[name] = [l for l in lines if l and l not in ('{', '}') and not l.startswith('.reg')]
    return funcs

def run(lines, inputs):
    R = {}
    for i, v in enumerate(inputs): R['%%%d' % (8 + i)] = v
    cf = 0
    def val(x):
        x = x.strip()
        return int(x) if re.fullmatch(r'\d+', x) else R[x]
    for l in lines:
        op, args = l.rstrip(';').split(None, 1)
        a = [x.strip() for x in args.split(',')]
        parts = op.split('.')
        base = parts[0]
        cc = 'cc' in parts
        if base in ('mul', 'mad', 'madc'):
            half = parts[1]
            prod = val(a[1]) * val(a[2])
            v = (prod & M) if half == 'lo' else (prod >> 32)
            if base != 'mul': v += val(a[3])
            if base == 'madc': v += cf
            if cc: cf = v >> 32
            R[a[0]] = v & M
        elif base in ('add', 'addc'):
            v = val(a[1]) + val(a[2]) + (cf if base == 'addc' else 0)
            if cc: cf = v >> 32
            R[a[0]] = v & M
        elif base in ('sub', 'subc'):
            v = val(a[1]) - val(a[2]) - (cf if base == 'subc' else 0)
            if cc: cf = 1 if v < 0 else 0
            R[a[0]] = v & M
        elif base == 'and':
            R[a[0]] = val(a[1]) & val(a[2])
        elif base == 'mov':
            R[a[0]] = val(a[1])
        else:
            raise ValueError(l)
    return sum(R['%%%d' % i] << (32 * i) for i in range(8))

def limbs(x): return [(x >> (32 * i)) & M for i in range(8)]

def main():
    f = parse(sys.argv[1])
    assert set(f) == {'fe_mul_ptx', 'fe_sq_ptx', 'fe_add_ptx', 'fe_sub_ptx'}, f.keys()
    edge = [0, 1, 2, 19, 38, P - 1, P, P + 1, 2**255, 2**256 - 1, 2**256 - 38, 2**256 - 39, 2**255 - 1, 2**224 * M]
    rnd = random.Random(7)
    vals = edge + [rnd.getrandbits(256) for _ in range(400)]
    bad = 0; n = 0
    for x in vals:
        for y in (edge + [rnd.getrandbits(256) for _ in range(6)]):
            for name, ref in (('fe_mul_ptx', x * y), ('fe_add_ptx', x + y), ('fe_sub_ptx', x - y)):
                r = run(f[name], limbs(x) + limbs(y))
                n += 1
                if r >= 2**256 or (r - ref) % P:
                    bad += 1
                    if bad < 5: print("MISMATCH", name, hex(x), hex(y), hex(r))
        r = run(f['fe_sq_ptx'], limbs(x)); n += 1
        if r >= 2**256 or (r - x * x) % P:
            bad += 1; print("MISMATCH sq", hex(x))
    print("ptx_sim: %d operations, %d mismatches" % (n, bad))
    sys.exit(1 if bad else 0)

main()

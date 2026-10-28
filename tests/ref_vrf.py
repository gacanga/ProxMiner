#!/usr/bin/env python3
"""ProxMiner - independent Python reference of the Proxima mining work function:
ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) output beta, stopped after Gamma.
Checked against the RFC 9381 Appendix B.4 vectors (H and beta)."""
import hashlib, sys

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
SQRTM1 = pow(2, (p - 1) // 4, p)
Gy = 4 * pow(5, p - 2, p) % p

def inv(x): return pow(x, p - 2, p)

def recover_x(y, sign):
    if y >= p:
        y %= p                       # non-canonical encodings accepted (filippo / dalek behaviour)
    u = (y * y - 1) % p
    v = (d * y * y + 1) % p
    x2 = u * inv(v) % p
    if x2 == 0:
        return 0                     # x = 0 (sign bit ignored, -0 = 0)
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * SQRTM1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x

# extended coordinates (X, Y, Z, T)
def padd(P, Q):
    X1, Y1, Z1, T1 = P; X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % p
    B = (Y1 + X1) * (Y2 + X2) % p
    C = T1 * 2 * d * T2 % p
    D = Z1 * 2 * Z2 % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)

def pmul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = padd(Q, P)
        P = padd(P, P)
        s >>= 1
    return Q

def encode(P):
    X, Y, Z, _ = P
    zi = inv(Z)
    x, y = X * zi % p, Y * zi % p
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')

def decode(b):
    y = int.from_bytes(b, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    y %= p
    return (x, y, 1, x * y % p)

def is_identity(P):
    X, Y, Z, _ = P
    return X % p == 0 and (Y - Z) % p == 0

G = decode(int.to_bytes(Gy, 32, 'little'))

def secret_scalar(seed):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32]); a[0] &= 248; a[31] &= 127; a[31] |= 64
    return int.from_bytes(a, 'little')

def public_key(seed):
    return encode(pmul(secret_scalar(seed), G))

def encode_to_curve(pk, alpha, first_ctr_only=False):
    for ctr in range(256):
        h = hashlib.sha512(bytes([3, 1]) + pk + alpha + bytes([ctr, 0])).digest()
        P = decode(h[:32])
        if P is not None:
            H = pmul(8, P)
            if not is_identity(H):
                return H, ctr
        if first_ctr_only:
            return None, ctr
    raise ValueError("no point")

def beta_of(seed, alpha, first_ctr_only=False):
    pk = public_key(seed)
    H, ctr = encode_to_curve(pk, alpha, first_ctr_only)
    if H is None:
        return None, ctr
    x = secret_scalar(seed) % L
    gamma = pmul(x, H)
    return hashlib.sha512(bytes([3, 3]) + encode(pmul(8, gamma)) + b'\x00').digest(), ctr

def trailing_zero_bits(beta):
    n = 0
    for b in reversed(beta):
        if b == 0:
            n += 8; continue
        while not (b & 1):
            b >>= 1; n += 1
        break
    return n

VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
     "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
     "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
     "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"),
]

def selftest():
    for sk, pk, alpha, h, beta in VECTORS:
        seed = bytes.fromhex(sk)
        assert public_key(seed).hex() == pk, "pk"
        H, _ = encode_to_curve(bytes.fromhex(pk), bytes.fromhex(alpha))
        assert encode(H).hex() == h, "H"
        b, _ = beta_of(seed, bytes.fromhex(alpha))
        assert b.hex() == beta, "beta"
    print("ref_vrf: RFC 9381 B.4 vectors OK (pk, H, beta)")

if __name__ == "__main__":
    selftest()

def check_cases(path):
    """lines: seed alpha pk ctr beta (from tests/core_test) -> recomputed independently"""
    n = bad = 0
    for line in open(path):
        seed, alpha, pk, ctr, beta = line.split()
        seed, alpha = bytes.fromhex(seed), bytes.fromhex(alpha)
        if public_key(seed).hex() != pk:
            bad += 1; print("pk mismatch"); continue
        b, c = beta_of(seed, alpha)
        if c != int(ctr) or b.hex() != beta:
            bad += 1; print("mismatch", alpha.hex(), c, ctr)
        n += 1
    print("ref_vrf --check: %d cases, %d mismatches" % (n, bad))
    return bad == 0

if __name__ == "__main__" and len(sys.argv) > 2 and sys.argv[1] == "--check":
    sys.exit(0 if check_cases(sys.argv[2]) else 1)

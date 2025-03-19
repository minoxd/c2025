import math
from itertools import combinations
from statistics import mode


def check_bin(arr: list[str]) -> bool:
    for n in arr:
        if '2' in n or '3' in n or '4' in n or '5' in n or '6' in n or '7' in n or '8' in n or '9' in n:
            return False
    return True


def dec_to_bin(n: str) -> str:
    n = int(n)
    ans = ''
    while n > 1:
        ans = str(n % 2) + ans
        n //= 2
    ans = str(n) + ans
    return ans


def bin_to_dec(n: str) -> str:
    if not check_bin(list(n)):
        return 'invalid'
    ans = 0
    for i in range(len(n)):
        digit = int(n[i])
        ans += (2 ** (len(n) - 1 - i)) * digit
    return str(ans)


def equalize_lengths(strings: list[str]) -> list[str]:
    max_length = max(len(s) for s in strings)
    return [s.zfill(max_length) for s in strings]


def xor(arr: list[str]) -> str:
    if not check_bin(arr):
        return 'invalid'
    arr = equalize_lengths(arr)
    arr = [list(s) for s in arr]
    ans = [str(sum(tuple(map(int, column))) % 2) for column in zip(*arr)]
    return ''.join(ans)


def ascii_array_to_str(arr: list[str]) -> str:
    arr = [int(e) for e in arr]
    l = len(arr)
    ans = ''
    for i in range(l):
        ans += chr(arr[i])
    return ans


def a5_1_key_gen(x: str, y: str, z: str, n: int) -> str:
    ans = ''
    for i in range(n):
        keystream_bit = xor([x[-1], y[-1], z[-1]])
        ans = ans + keystream_bit
        majority = mode([x[8], y[10], z[10]])
        if x[8] == majority:
            x = ' ' + x[:-1]
            x = xor([x[13], x[16], x[17], x[18]]) + x[1:]
        if y[10] == majority:
            y = ' ' + y[:-1]
            y = xor([y[20], y[21]]) + y[1:]
        if z[10] == majority:
            z = ' ' + z[:-1]
            z = xor([z[7], z[20], z[21], z[22]]) + z[1:]
    return ans


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def find_relatively_prime_pairs(arr: list[int]) -> list[tuple[int, int]]:
    return [(a, b) for a, b in combinations(arr, 2) if math.gcd(a, b) == 1]


def check_relatively_prime(a: int, b: int) -> bool:
    if math.gcd(a, b) == 1:
        return True
    return False


def square_n_multiply_for_modular_exponentiation(x: int, h: int, n: int) -> int:
    if h == 0 and n == 1:
        return 0
    if h == 0:
        return 1
    if h == 1:
        return x % n
    r = x
    h = dec_to_bin(str(h))
    t = len(h)
    for i in range(1, t):
        r = (r ** 2) % n
        if h[i] == '1':
            r = (r * x) % n
    return r


# todo: extended euclidian
def find_modular_multiplicative_inverse(x: int, n: int) -> int:
    if not check_relatively_prime(x, n):
        raise ValueError('not relatively prime numbers')
    for i in range(n):
        if (x * i) % n == 1:
            return i


def check_modular_multiplicative_inverse(e: int, d: int, modulo: int) -> bool:
    if (e * d) % modulo == 1:
        return True
    return False


def str_to_int(s: str) -> int:
    return int.from_bytes(s.encode('ascii'))


def int_to_str(n: int) -> str:
    return n.to_bytes((n.bit_length() + 7) // 8).decode('ascii')


def rsa_crypto_system(p: int, q: int, e: int = None, d: int = None, m: int = None, c: int = None):
    if e is None and d is None:  # todo: all e and d possible
        raise ValueError('either e or d must be specified')
    if m is None and c is None:
        raise ValueError('either m or c must be specified')
    n = p * q
    modulo = (p - 1) * (q - 1)
    # provided e and d
    if e and d:
        # verify e
        if not check_relatively_prime(e, modulo):
            raise ValueError('e is invalid')
        # verify d
        if not check_modular_multiplicative_inverse(e, d, modulo):
            raise ValueError('d is invalid')
    # provided e
    if e:
        if not check_relatively_prime(e, modulo):
            raise ValueError('e is invalid')
        d = find_modular_multiplicative_inverse(e, modulo)
    # provided d
    if d:
        e = find_modular_multiplicative_inverse(d, modulo)
        if not check_relatively_prime(e, modulo):
            raise ValueError('d is invalid: ')
    # provided m and c
    if m and c:
        if m == square_n_multiply_for_modular_exponentiation(c, d, n):
            raise ValueError('m and c are invalid')
    # provided m
    if m:
        return square_n_multiply_for_modular_exponentiation(m, e, n)
    # provided c
    if c:
        return square_n_multiply_for_modular_exponentiation(c, d, n)


class Elgamal:
    def __init__(self, d, p, a):
        self.d = d
        self.p = p
        self.a = a
        self.b = pow(self.a, self.d, self.p)
        print(f'large prime: p = {self.p}')
        print(f'primitive element of Z*_p or of subgroup of Z*_p: alpha ={self.a}')
        print(f'random integer (2,3,...,p-2): d = {self.d}')
        print(f'private key: {self.d}, public key: {(self.p, self.a, self.b)}')
        self.x = None
        self.ke = None
        self.ke_inverse = None
        self.r = None
        self.s = None

    def set_ephemeral(self, ke):
        self.ke = ke
        print(f'ephemeral key gcd(ke,p-1) = 1: ke = {self.ke}')

    def sign(self, x):
        self.x = x
        self.r = pow(self.a, self.ke, self.p)
        self.ke_inverse = find_modular_multiplicative_inverse(self.ke, self.p - 1)
        self.s = pow((self.x - self.d * self.r) * self.ke_inverse, 1, self.p - 1)
        print('r = a^ke mod p')
        print(f'{self.r} = {self.a}^{self.ke} mod {self.p}')
        print('s = (x - dr)ke_inverse mod p - 1')
        print(f'{self.s} = ({self.x} - {self.d}*{self.r}) * {self.ke_inverse} mod {self.p} - 1')
        print(f'signature: {(self.r, self.s)}')

    def verify(self, x, r, s):
        t = pow(pow(self.b, r, self.p) * pow(r, s, self.p), 1, self.p)
        pow_a_x = pow(self.a, x, self.p)
        print('t = b^r * r^s mod p')
        print(f'{t} = {self.b}^{r} * {r}^{s} mod {self.p}')
        print('a^x')
        print(f'{pow_a_x} = {self.a}^{x}')
        print(f'a^x: {pow_a_x}, t: {t}, result: {t == pow_a_x}')

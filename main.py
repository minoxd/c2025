from icecream import ic

from utils import dec_to_bin, bin_to_dec, ascii_array_to_str, a5_1_key_gen, xor, gcd, \
    find_relatively_prime_pairs, square_n_multiply_for_modular_exponentiation, find_modular_multiplicative_inverse, \
    rsa_crypto_system, str_to_int, int_to_str, Elgamal


# input: 2 decimal numbers, output: aXORb in binary form and aXORb in decimal form
def lab1_1(a: int, b: int):
    a = str(a)
    b = str(b)
    bin_a = dec_to_bin(a)
    bin_b = dec_to_bin(b)
    bin_a_xor_b = xor([bin_a, bin_b])
    dec_a_xor_b = bin_to_dec(bin_a_xor_b)
    return bin_a_xor_b, dec_a_xor_b


# input: array of ascii codes, output: string
def lab1_2(arr: list[int]) -> str:
    arr = [str(e) for e in arr]
    return ascii_array_to_str(arr)


# input: array of decimal numbers and key in decimal form, output: string
def lab1_3(k: int, arr: list[int]) -> str:
    # convert input to binary
    k = str(k)
    k = dec_to_bin(k)
    arr = [str(e) for e in arr]
    arr = [dec_to_bin(e) for e in arr]
    # find hidden array of elements, remember if aXORb = c then a = bXORc
    hidden_arr = [xor([k, e]) for e in arr]
    ans = ascii_array_to_str([bin_to_dec(e) for e in hidden_arr])
    return ans


def lab1_4(x: int, y: int, z: int, n: int) -> str:
    x = str(x)
    y = str(y)
    z = str(z)
    return a5_1_key_gen(dec_to_bin(x), dec_to_bin(y), dec_to_bin(z), n)


def lab2_1(a: int, b: int) -> int:
    return gcd(a, b)


def lab2_2(arr: list[int]) -> list[tuple[int, int]]:
    return find_relatively_prime_pairs(arr)


def lab2_3(x: int, h: int, n: int) -> int:
    return square_n_multiply_for_modular_exponentiation(x, h, n)


def lab2_4(x: int, n: int) -> int:
    return find_modular_multiplicative_inverse(x, n)


def lab3_1(s: str) -> int:
    return str_to_int(s)


def lab3_2(n: int) -> str:
    return int_to_str(n)


def lab3_3_1(p: int, q: int, e: int, m: int) -> int:
    return rsa_crypto_system(p, q, e=e, m=m)


def lab3_3_2(p: int, q: int, d: int, c: int) -> int:
    return rsa_crypto_system(p, q, d=d, c=c)


def lab3_4(c: int, p: int, q: int, e: int) -> str:
    return int_to_str(rsa_crypto_system(81401, 27109, e=65537, c=412589464))


def main():
    # ic(lab1_1(123, 543))
    # ic(lab1_2(
    #     [105, 110, 116, 114, 111, 50, 99, 114, 121, 112, 116, 111, 123, 119, 51, 108, 99, 48, 109, 51, 95, 116, 48, 95,
    #      106, 48, 117, 114, 110, 51, 121, 125]))
    # ic(lab1_3(10,
    #           [99, 100, 126, 120, 101, 56, 105, 120, 115, 122, 126, 101, 113, 59, 121, 126, 57, 122, 85, 58, 100, 85,
    #            96,
    #            58, 127, 120, 100, 57, 115, 119]))
    # ic(lab1_4(513365, 3355443, 7401712, 10))
    # ic(lab2_1(52698, 61430))
    # ic(lab2_2([290345, 218585, 143231, 164172, 155768, 423151, 239707, 153544, 287390, 480837]))
    # ic(lab2_3(856,25,7))
    # ic(lab2_4(65537,35256))
    # ic(lab3_1('flow'))
    # ic(lab3_2(14445))
    # ic(lab3_3_1(251, 191, 65537, 26729))
    # ic(lab3_3_1(233, 151, 9473, 29600))
    # ic(lab3_4(412589464, 81401, 27109, 65537))
    # elgamal = Elgamal(d=127, p=593, a=2)
    # elgamal.set_ephemeral(ke=215)
    # elgamal.sign(x=5022)
    # elgamal.verify(x=82, r=227, s=342)
    # alice = Elgamal(d=127, p=593, a=2)
    # bob = Elgamal(d=127, p=593, a=2)
    # alice.set_ephemeral(ke=213)
    # bob.set_ephemeral(ke=215)
    # alice.sign(x=5 * 2602 + 1)
    # bob.sign(x=5 * 2022 + 2)
    # ic(square_n_multiply_for_modular_exponentiation(66,470,907))
    elgamal = Elgamal(d=59, p=877,a=6)
    elgamal.set_ephemeral(125)
    elgamal.sign(517)
    elgamal.verify(696,760,632)
    elgamal.verify(696,771,819)
    pass


if __name__ == '__main__':
    main()

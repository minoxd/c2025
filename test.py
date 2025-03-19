def greatest_common_divisor(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a

def euler(number: int) -> int:
    return sum([1 for i in range(1, number) if greatest_common_divisor(i, number) == 1])

if __name__ == "__main__":
    print(euler(67))
    print(euler(10))
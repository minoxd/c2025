import random
from math import gcd


# Modular exponentiation
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)


# Modular inverse using extended Euclidean algorithm
def mod_inverse(var, mod):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_result, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_result, x, y

    _, inv, _ = extended_gcd(var, mod)
    return (inv % mod + mod) % mod


# Check if a number is prime (simple test for small numbers)
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


# Generate small prime numbers for demo
def generate_prime():
    while True:
        num = random.randint(10, 50)  # Small range for demo
        if is_prime(num):
            return num


# Hash message to a number
# def hash_message(message):
#     return int(hashlib.sha256(message.encode()).hexdigest(), 16)


class Elgamal:
    def __init__(self, d, p, alpha):
        self.private_key = None
        self.public_key = None
        self.generate_keys(p, alpha, d)

    def generate_keys(self, p, alpha, d=None):
        if d is None:
            d = random.randint(1, p - 2)  # Private key
        beta = mod_exp(alpha, d, p)  # Public key
        self.public_key = (p, alpha, beta)
        self.private_key = d

    def sign_message(self, message, ke=None):
        d = self.private_key
        p, alpha, _ = self.public_key
        # h = hash_message(message) % (p-1)  # Hash mod p-1
        if ke is None:
            while True:
                ke = random.randint(1, p - 2)
                if gcd(ke, p - 1) == 1:  # Ensure ke is coprime with p-1
                    break
        if gcd(ke, p - 1) != 1:  # Ensure ke is coprime with p-1
            return
        ke_inv = mod_inverse(ke, p - 1)
        r = mod_exp(alpha, ke, p)
        s = (message - d * r) * ke_inv % (p - 1)
        return (
            r, s), f"for message is {message} and Ephemeral Key is {ke} and Mod Inverse of Ephemeral Key is {ke_inv}"

    def verify_signature(self, message, signature):
        p, alpha, beta = self.public_key
        r, s = signature
        if not (0 < r < p and 0 < s < p - 1):
            return False
        # h = hash_message(message) % (p-1)
        v1 = (mod_exp(beta, r, p) * mod_exp(r, s, p)) % p
        v2 = mod_exp(alpha, message, p)
        return v1 == v2, f"{v1} vs {v2}, for message is {message} and signature is {signature}"

    def print_keys(self):
        print(f"Public Key: {self.public_key}")
        print(f"Private Key: {self.private_key}")


class RSA:
    def __init__(self, p, q, e=None):
        self.private_key = None
        self.public_key = None
        self.generate_keys(p, q, e)

    def generate_keys(self, p=None, q=None, e=None):
        if p is None and q is None:
            p = generate_prime()
            q = generate_prime()
            while p == q:
                q = generate_prime()
        if p is None or q is None or p == q:
            print("Either missing p or q or p is equal to q")
            return

        n = p * q
        phi = (p - 1) * (q - 1)

        if e is None:
            while True:
                e = random.randint(2, phi - 1)
                if gcd(e, phi) == 1:
                    break

        d = mod_inverse(e, phi)
        self.public_key = (n, e)
        self.private_key = d
        print(f"Totient: {phi}")

    # Sign message
    def sign_message(self, message):
        n, _ = self.public_key
        d = self.private_key
        # h = hash_message(message) % n  # Hash mod n to keep it in range
        s = mod_exp(message, d, n)
        return s, f"for message is {message} and Modulus is {n} (message to the d-th)"

    # Verify signature
    def verify_signature(self, message, signature):
        n, e = self.public_key
        # h = hash_message(message) % n
        v = mod_exp(signature, e, n)
        return v == message, f"{v} vs {message} and signature is {signature}"

    def print_keys(self):
        print(f"Public Key: {self.public_key}")
        print(f"Private Key: {self.private_key}")


class CAElgamal:
    def __init__(self, elgamal: Elgamal):
        self.elgamal = elgamal

    def issue_cert(self, user_identity, user_public_key, ke, message):
        signature, _ = self.elgamal.sign_message(message, ke=ke)
        issued_cert = {
            "cert": {
                "identity": user_identity,
                "public_key": user_public_key,
            },
            "signature": signature,
        }
        print(f"Issued Certificate: {issued_cert}")
        return issued_cert

    def verify_cert(self, message, signature):
        is_valid, _ = self.elgamal.verify_signature(message, signature)
        print(f"Valid: {is_valid}")


class CARSA:
    def __init__(self, rsa: RSA):
        self.rsa = rsa

    def issue_cert(self, user_identity, user_public_key, message):
        signature, _ = self.rsa.sign_message(message)
        issued_cert = {
            "cert": {
                "identity": user_identity,
                "public_key": user_public_key,
            },
            "signature": signature,
        }
        print(f"Issued Certificate: {issued_cert}")
        return issued_cert

    def verify_cert(self, message, signature):
        is_valid, _ = self.rsa.verify_signature(message, signature)
        print(f"Valid: {is_valid}")

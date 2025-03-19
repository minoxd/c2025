from better_utils import Elgamal, RSA, CAElgamal, CARSA


def elgamal_crypto_system():
    elgamal = Elgamal(d=59, p=877, alpha=6)

    message = 517
    signature, explain_sign = elgamal.sign_message(message, ke=125)
    is_valid, explain_verify = elgamal.verify_signature(message, signature)

    elgamal.print_keys()
    print(f"Signature: {signature}, ({explain_sign})")
    print(f"Signature Valid: {is_valid}, ({explain_verify})")

    print("---\nFurther experiments:")
    is_valid, explain_verify = elgamal.verify_signature(message=696, signature=(760, 632))
    print(f"Signature Valid: {is_valid}, ({explain_verify})")
    is_valid, explain_verify = elgamal.verify_signature(message=696, signature=(771, 819))
    print(f"Signature Valid: {is_valid}, ({explain_verify})")

    return elgamal


def certificate_authority_elgamal():
    elgamal = elgamal_crypto_system()
    user_identity = 1
    user_public_key = 663
    ke = 113
    message = 470 * user_public_key + user_identity
    ca_elgamal = CAElgamal(elgamal)
    issued_cert = ca_elgamal.issue_cert(user_identity=user_identity, user_public_key=user_public_key, ke=ke,
                                        message=message)
    ca_elgamal.verify_cert(message=message, signature=issued_cert['signature'])


def rsa_crypto_system():
    rsa = RSA(251, 191, 3)

    message = 124
    signature, explain_sign = rsa.sign_message(message)
    is_valid, explain_verify = rsa.verify_signature(message, signature)

    rsa.print_keys()
    print(f"Signature: {signature}, ({explain_sign})")
    print(f"Signature Valid: {is_valid}, ({explain_verify})")

    return rsa


def certificate_authority_rsa():
    rsa = rsa_crypto_system()
    user_identity = None
    user_public_key = None
    message = None
    ca_rsa = CARSA(rsa)
    issued_cert = ca_rsa.issue_cert(user_identity=user_identity, user_public_key=user_public_key, message=message)
    ca_rsa.verify_cert(message=message, signature=issued_cert['signature'])


def main():
    # elgamal_crypto_system()
    # rsa_crypto_system()
    certificate_authority_elgamal()
    # certificate_authority_rsa()


if __name__ == '__main__':
    main()

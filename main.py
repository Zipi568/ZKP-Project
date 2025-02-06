import random
from typing import Tuple, List
from py_ecc.optimized_bls12_381 import G1, G2, pairing, curve_order, multiply, add, neg
from sympy import symbols, div, expand

def generate_GT():
    """
    Generate a GT group element using pairing.
    """
    g = G1
    h = G2
    gt_generator = pairing(g, h)

    # Verify that gt_generator is in GT
    # Ensure that gt_generator raised to curve_order equals 1
    assert gt_generator ** curve_order == 1, "GT generator is not valid"

    return gt_generator


def setup(k: int, t: int) -> Tuple[dict, int]:
    """
    Setup function for bilinear pairing-based cryptosystem.

    Parameters:
    - k: Security parameter (not directly used here as we rely on BLS12-381 parameters).
    - t: Parameter for t-SDH assumption.

    Returns:
    - PK: Public key.
    - SK: Secret key.
    """
    # Step 1: Define the generator for G1
    g = G1
    h = G2  # Optional: For completeness, define G2's generator
    print("G1 Generator:", g)
    print("G2 Generator:", h)

    # Step 2: Choose a random secret key alpha from Z*_p
    alpha = random.randint(1, curve_order - 1)

    # Step 3: Compute the tuple (g^alpha, g^(alpha^2), ..., g^(alpha^t)) in G
    g_alpha_tuple = [multiply(g, pow(alpha, i, curve_order)) for i in range(1, t + 1)]

    # Step 4: Generate GT generator
    gt_gen = generate_GT()
    print("GT Generator:", gt_gen)

    # Step 5: Construct the public key
    PK = {
        "G1": G1,
        "G2": G2,
        "GT": gt_gen,
        "g": g,
        "g_alpha_tuple": g_alpha_tuple,
    }

    # Step 6: Return public key and secret key
    return PK, alpha


# Example usage
security_param = 128  # 128-bit security
t_param = 5  # t-SDH assumption parameter

tau = random.randint(1, 2**256 - 1)  # Nasumično biran skalar

# 2. Generisanje Powers of Tau (potrebno za komitment)
def setup(degree, G, tau):
    """
    Generiše javne parametre do stepena 'degree' za polinomialni komitment.
    """
    return [multiply(G, pow(tau, i)) for i in range(degree + 1)]

# Postavljanje javnih parametara za polinom stepena 3
trusted_setup = setup(3, G1, tau)

def commit(trusted_setup, coeffs):
    C = None  # Neutralna tačka na eliptičkoj krivoj

    for i, coef in enumerate(coeffs):
        term = multiply(trusted_setup[i], coef)  # c_i * (tau^i * G)
        if C:
            C = add(C, term)
        else:
            C = term
    return C

def generate_witness(PK, polynom, i):
    x = symbols('x')
    phi_i = polynom.subs(x, i)  # Evaluacija phi(i)
    numerator = expand(polynom - phi_i)  # Racunamo phi(x) - phi(i)
    denominator = x - i  # (x - i)
    psi_i, remainder = div(numerator, denominator, x)  # Deljenje polinoma
    return psi_i

def verify_polynom(PK, C, coeffs):
    C_prime = commit(PK, coeffs)
    return C == C_prime

def verify_eval(C, i, phi_i, w_i, g, g_alpha):
    lhs = pairing(C, g)  # e(C, g)
    rhs = pairing(w_i, add(g_alpha, neg(multiply(G1, i)))) * pairing(g, g) ** phi_i  # e(w_i, g^alpha / g^i) * e(g, g)^phi(i)
    return lhs == rhs

coeffs = [4, 7, 2, 1]  # 4 * x^3 + 7 * x^2 + 2 * x + 1
fake_coeffs = [4, 6, 2, 4]

# Ispis rezultata setup faze
C = commit(trusted_setup, coeffs)
print("type: ", type(C[0]))
x = symbols('x')
polynom = 4 * x**3 + 7 * x**2 + 2 * x + 1

op = verify_polynom(trusted_setup, C, coeffs)
print("Commitment C:", C)
print("Open:", op)
witness = generate_witness(trusted_setup, polynom, 4)
print("Witness: {} -> {}", 4, witness)
verification = verify_eval(C, 4, polynom, witness, G1, G2)

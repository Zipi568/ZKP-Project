import random
from typing import Tuple, List
from py_ecc.optimized_bls12_381 import G1, G2, pairing, curve_order, multiply, add, neg, is_on_curve, normalize, Z1, b
from sympy import symbols, div, expand, poly

def generate_GT():
    """
    Generate a GT group element using pairing.
    """
    g = G1
    h = G2
    gt_generator = pairing(h, g)

    # Verify that gt_generator is in GT
    # Ensure that gt_generator raised to curve_order equals 1
    #assert gt_generator ** curve_order == 1, "GT generator is not valid"

    return gt_generator

def trusted_setup(k: int, t: int) -> Tuple[dict, int]:
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

    # Step 2: Choose a random secret key alpha from Z*_p
    alpha = random.randint(1, curve_order - 1)

    # Step 3: Compute the tuple (g^alpha, g^(alpha^2), ..., g^(alpha^t)) in G
    g_alpha_tuple = [multiply(g, pow(alpha, i, curve_order)) for i in range(0, t + 1)]

    # Step 4: Generate GT generator
    gt_gen = generate_GT()

    # Step 5: Construct the public key
    PK = {
        "G1": G1,
        "G2": G2,
        "GT": gt_gen,
        "g": g,
        "alpha": alpha,
        "g_alpha_tuple": g_alpha_tuple,
    }

    # Step 6: Return public key and secret key
    return PK, alpha



def commit(trusted_setup, polynom):
    x = symbols('x')
    p_i = polynom.subs(x, trusted_setup["alpha"])
    C = multiply(G1, p_i)
    return C
def generate_witness(PK, polynom, i, alpha):
    x = symbols('x')
    phi_i = polynom.subs(x, i)  # Evaluacija phi(i)
    numerator = expand(polynom - phi_i)  # Racunamo phi(x) - phi(i)
    denominator = x - i  # (x - i)
    psi_i, remainder = div(numerator, denominator, x)  # Deljenje polinoma
    #mozda ovo popraviti
    print("Psi_i: ", psi_i)
    assert remainder == 0

    eval_alpha = psi_i.subs(x, alpha)
    wi = multiply(G1, eval_alpha)

    return wi, psi_i

def verify_polynom(PK, C, coeffs):
    C_prime = commit(PK, coeffs)
    return C == C_prime

def verify_eval(PK, C, i, phi_i, w_i, psi_i):
    lhs = pairing(G2, C)  # e(C, g)
    x = symbols('x')
    p_i = phi_i.subs(x, i)
    print("LHS: {0}".format(lhs))
    d1 = multiply(G2, PK["alpha"] - i)

    p1 = pairing(d1, w_i)
    rhs = p1 * (pairing(G2, G1) ** p_i)  # e(w_i, g^alpha / g^i) * e(g, g)^phi(i)
    print("RHS: {0}".format(rhs))

    rhs1 = pairing(G2, G1)
    rhs1 = rhs1 ** p_i

    alpha = psi_i.subs(x, PK["alpha"])
    s1 = multiply(G1, alpha)
    par = pairing(d1, s1)

    u = par * rhs1

    print("RHS1: {0}".format(u))
    equal = lhs == u

    print("Equal: ", equal)
    return lhs == rhs




# Example usage
security_param = 128  # 128-bit security
t_param = 5  # t-SDH assumption parameter

s, alpha = trusted_setup(security_param, t_param)

x = symbols('x')
polynom = 4 * x**3 + 7 * x**2 + 2 * x + 1

for i in s:
    print("Tr setup: {0} -> {1}".format(i, s[i]))
print(alpha)

coeffs = [4, 7, 2, 1]  # 4 * x^3 + 7 * x^2 + 2 * x + 1
commitment = commit(s, polynom)
print("Commitment: {0}".format(commitment))



fake_coeffs = [4, 6, 2, 4]

# Ispis rezultata setup faze
#ok = verify_polynom(s, commitment, coeffs)
#print(ok)
witness, psi_i = generate_witness(s, polynom, 3, alpha)

pripada = is_on_curve(witness, b)
print("Pripada commit: {}".format(pripada))

print("Witness type: {0}".format(type(witness)))
print("Witness: {0}".format(witness))
verification = verify_eval(s, commitment, 3, polynom, witness, psi_i)
print(verification)

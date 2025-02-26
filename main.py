import random
from typing import Tuple, List
from py_ecc.optimized_bls12_381 import G1, G2, pairing, curve_order, multiply, add, neg, is_on_curve, normalize, Z1, b, Z2
from sympy import symbols, div, expand, Poly
from functools import reduce
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
    list = []
    for i in range(0, t + 1):
        list.append(multiply(G1, pow(alpha, i, curve_order)))
    # Step 4: Generate GT generator
    gt_gen = generate_GT()
    list2 = []
    for i in range(0, t + 1):
        list2.append(multiply(G2, pow(alpha, i, curve_order)))
    # Step 5: Construct the public key
    PK = {
        "G1": G1,
        "G2": G2,
        "GT": gt_gen,
        "g2_alpha_tuple": list2,
        "g_alpha_tuple": list,
    }

    # Step 6: Return public key and secret key
    return PK, alpha



def commit(trusted_setup, polynom):
    coeffs = Poly(polynom).all_coeffs()
    coeffs.reverse()
    length = len(coeffs)
    C1 = [multiply(trusted_setup["g_alpha_tuple"][j], coeffs[j]) for j in range(0, length)]
    K = C1[0]
    for j in range(1, length):
        K = add(K, C1[j])
        print("Tr[{1}]: {0}, j: {1}, coef: {2}".format(trusted_setup["g_alpha_tuple"][j], j, coeffs[j]))
    print("C1: ", K)
    return K


def generate_witness(PK, polynom, i):
    x = symbols('x')
    phi_i = polynom.subs(x, i)  # Evaluacija phi(i)
    numerator = expand(polynom - phi_i)  # Racunamo phi(x) - phi(i)
    denominator = x - i  # (x - i)
    psi_i, remainder = div(numerator, denominator, x)  # Deljenje polinoma
    #mozda ovo popraviti
    print("Psi_i: ", psi_i)
    assert remainder == 0

    coeffs = Poly(psi_i).all_coeffs()
    coeffs.reverse()
    length = len(coeffs)
    print("Z2:", Z2, "Tip:", type(Z2[0]))
    wi = Z2
    print("TIP: ", type(wi[0]))
    for j in range(0, length):
        wi = add(wi, multiply(PK["g2_alpha_tuple"][j], int(coeffs[j])))
    return wi, psi_i

def verify_polynom(PK, C, coeffs):
    C_prime = commit(PK, coeffs)
    return C == C_prime

def verify_eval(PK, C, i, phi_i, w_i):
    lhs = pairing(G2, C)  # e(C, g)
    x = symbols('x')
    p_i = phi_i.subs(x, i)
    print("LHS: {0}".format(lhs))
    d1 = add(PK["g_alpha_tuple"][1], neg(multiply(G1, i)))

    p1 = pairing(w_i, d1)
    rhs = p1 * (pairing(G2, G1) ** p_i)  # e(w_i, g^alpha / g^i) * e(g, g)^phi(i)
    print("RHS: {0}".format(rhs))

    rhs1 = pairing(G2, G1)
    rhs1 = rhs1 ** p_i


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
witness, psi_i = generate_witness(s, polynom, 3)

#pripada = is_on_curve(witness, b)
#print("Pripada commit: {}".format(pripada))

print("Witness type: {0}".format(type(witness)))
print("Witness: {0}".format(witness))
verification = verify_eval(s, commitment, 3, polynom, witness)
print(verification)


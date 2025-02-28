import random
from typing import Tuple, List
from py_ecc.optimized_bls12_381 import G1, G2, pairing, curve_order, multiply, add, neg, is_on_curve, normalize, Z1, b, Z2, b2
from sympy import symbols, div, expand, Poly
from functools import reduce
def generate_GT():

    gt_generator = pairing(G2, G1)

    return gt_generator

def trusted_setup(k: int, t: int) -> Tuple[dict, int]:

    alpha = random.randint(2 ** k, curve_order - 1)

    list = [multiply(G1, pow(alpha, i, curve_order)) for i in range(0, t + 1)]

    gt_gen = generate_GT()
    list2 = [multiply(G2, pow(alpha, i, curve_order)) for i in range(0, t + 1)]

    PK = {
        "G1": G1,
        "G2": G2,
        "GT": gt_gen,
        "g2_alpha_tuple": list2,
        "g_alpha_tuple": list,
    }

    return PK



def commit(trusted_setup, polynom):

    coeffs = Poly(polynom).all_coeffs()
    coeffs.reverse()
    length = len(coeffs)

    C = Z1

    for j in range(0, length):
        C = add(C, multiply(trusted_setup["g_alpha_tuple"][j], coeffs[j]))

    return C


def generate_witness(PK, polynom, i):
    x = symbols('x')
    phi_i = polynom.subs(x, i)
    numerator = expand(polynom - phi_i)
    denominator = x - i
    psi_i, remainder = div(numerator, denominator, x)

    assert remainder == 0

    coeffs = Poly(psi_i).all_coeffs()
    coeffs.reverse()
    length = len(coeffs)

    wi = Z2

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
    d1 = add(PK["g_alpha_tuple"][1], neg(multiply(G1, i)))

    p1 = pairing(w_i, d1)
    rhs = p1 * (pairing(G2, G1) ** p_i)  # e(w_i, g^alpha / g^i) * e(g, g)^phi(i)

    return lhs == rhs


security_param = 128  # 128-bit security
t_param = 5  # t-SDH assumption parameter

PK = trusted_setup(security_param, t_param)
for s in PK:
    print(s, ": ", PK[s])

x = symbols('x')
polynom = 4 * x**3 + 7 * x**2 + 2 * x + 1

commitment = commit(PK, polynom)
print("Commitment: {0}".format(commitment))

i = 4
print("Evaluacija u tacki:", i)

witness, psi_i = generate_witness(PK, polynom, i)

assert is_on_curve(witness, b2)

verification = verify_eval(PK, commitment, i, polynom, witness)
print("Verification: ", verification)


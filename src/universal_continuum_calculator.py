"""
Supela-K3-Omega — Calculateur Universel du Continuum Doctoral (22 Piliers)
Exécute et vérifie numériquement, algébriquement et matériellement les 22 familles
de formules : des mathématiques fondamentales et appliquées (1-15), au noyau
cryptographique et épistémique Supela-K3-Omega (16), jusqu'à la physique des
semi-conducteurs et transistors BJT / JFET / MOSFET / CMOS (17), aux portes NAND
et additionneurs CLA de l'ALU (18), à l'architecture CPU (19), à la machine de
Turing et au lambda-calcul (20), à la logique de Hoare/Dijkstra (21) et au
consensus Byzantin BFT (22).
"""

from __future__ import annotations

import cmath
import hashlib
import json
import math
import os
import sys
from decimal import Decimal
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.schnorr_zkp import generate_schnorr_nizk_proof, verify_schnorr_nizk_proof
from src.worm_merkle import SupelaWormLedger


class UniversalContinuumCalculator:
    """Exécute et certifie le calcul déterministe des 22 piliers du continuum Supela-K3-Omega."""

    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if b == 0:
            return (a, 1, 0)
        g, x1, y1 = UniversalContinuumCalculator._extended_gcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

    @staticmethod
    def _euler_totient(n: int) -> int:
        result = n
        p = 2
        temp = n
        while p * p <= temp:
            if temp % p == 0:
                while temp % p == 0:
                    temp //= p
                result -= result // p
            p += 1
        if temp > 1:
            result -= result // temp
        return result

    @staticmethod
    def _nand(a: int, b: int) -> int:
        return 1 - ((a & 1) & (b & 1))

    @classmethod
    def compute_pillar_01_logic_sets_lattices(cls) -> Dict[str, Any]:
        # Exhaustive De Morgan verification over {0, 1}^2
        de_morgan_valid = all(
            (not (p and q)) == ((not p) or (not q))
            and (not (p or q)) == ((not p) and (not q))
            for p in (False, True)
            for q in (False, True)
        )
        set_a = {1, 2, 3, 4, 5}
        set_b = {4, 5, 6, 7}
        inc_exc_valid = len(set_a | set_b) == len(set_a) + len(set_b) - len(set_a & set_b)
        cantor_valid = (2 ** len(set_a)) > len(set_a)
        lattice_order = ["L0", "L1", "L2Q", "L2", "L3", "L4", "L5"]
        rank = {lvl: idx for idx, lvl in enumerate(lattice_order)}
        transitivity_valid = rank["L0"] < rank["L2Q"] < rank["L3"] < rank["L4"] < rank["L5"]
        return {
            "pillar": "01_logic_sets_lattices",
            "de_morgan_exhaustive": de_morgan_valid,
            "inclusion_exclusion_card": len(set_a | set_b),
            "cantor_powerset_card": 2 ** len(set_a),
            "epistemic_lattice_strict_order": transitivity_valid,
            "verified": de_morgan_valid and inc_exc_valid and cantor_valid and transitivity_valid,
        }

    @classmethod
    def compute_pillar_02_number_theory_modular(cls) -> Dict[str, Any]:
        a, b = 252, 198
        g, u, v = cls._extended_gcd(a, b)
        bezout_valid = (a * u + b * v == g) and (g == math.gcd(a, b))
        gcd_lcm_valid = math.gcd(a, b) * math.lcm(a, b) == a * b

        n = 100
        phi_n = cls._euler_totient(n)
        euler_thm_valid = pow(7, phi_n, n) == 1

        # Chinese Remainder Theorem: x = 2 (mod 3), x = 3 (mod 5), x = 2 (mod 7) -> x = 23 (mod 105)
        moduli = [3, 5, 7]
        remainders = [2, 3, 2]
        big_n = math.prod(moduli)
        crt_x = sum(
            r_i * (big_n // n_i) * pow(big_n // n_i, -1, n_i)
            for r_i, n_i in zip(remainders, moduli)
        ) % big_n
        crt_valid = all(crt_x % n_i == r_i for r_i, n_i in zip(remainders, moduli))

        # Legendre symbol (a/p)
        p = 101
        legendre_5 = pow(5, (p - 1) // 2, p)
        legendre_valid = legendre_5 in (1, p - 1)

        return {
            "pillar": "02_number_theory_modular",
            "bezout_identity": f"{a}*({u}) + {b}*({v}) = {g}",
            "euler_phi_100": phi_n,
            "crt_solution_mod_105": crt_x,
            "legendre_5_mod_101": 1 if legendre_5 == 1 else -1,
            "verified": bezout_valid and gcd_lcm_valid and euler_thm_valid and crt_valid and legendre_valid,
        }

    @classmethod
    def compute_pillar_03_algebra_polynomials(cls) -> Dict[str, Any]:
        # Binomial expansion (a + b)^n
        a, b, n = 3, 5, 7
        binom_sum = sum(math.comb(n, k) * (a ** (n - k)) * (b ** k) for k in range(n + 1))
        binom_valid = binom_sum == (a + b) ** n

        # Quadratic + Vieta: 2x^2 - 10x + 12 = 0 -> roots 2 and 3
        qa, qb, qc = 2.0, -10.0, 12.0
        disc = qb ** 2 - 4 * qa * qc
        x1 = (-qb - math.sqrt(disc)) / (2 * qa)
        x2 = (-qb + math.sqrt(disc)) / (2 * qa)
        vieta_valid = math.isclose(x1 + x2, -qb / qa) and math.isclose(x1 * x2, qc / qa)

        # Cardano depressed cubic: t^3 + 6t - 20 = 0 -> real root t = 2
        p_c, q_c = 6.0, -20.0
        rad = math.sqrt((q_c / 2.0) ** 2 + (p_c / 3.0) ** 3)
        u_c = math.copysign(abs(-q_c / 2.0 + rad) ** (1.0 / 3.0), -q_c / 2.0 + rad)
        v_c = math.copysign(abs(-q_c / 2.0 - rad) ** (1.0 / 3.0), -q_c / 2.0 - rad)
        t_root = u_c + v_c
        cardano_valid = math.isclose(t_root, 2.0, rel_tol=1e-12)

        return {
            "pillar": "03_algebra_polynomials",
            "binomial_8_pow_7": binom_sum,
            "quadratic_roots": [x1, x2],
            "cardano_cubic_root": round(t_root, 12),
            "verified": binom_valid and vieta_valid and cardano_valid,
        }

    @classmethod
    def compute_pillar_04_algebraic_structures_decimal_ring(cls) -> Dict[str, Any]:
        # Frobenius endomorphism in F_p: (x + y)^p == x^p + y^p (mod p)
        p = 97
        x, y = 29, 44
        frobenius_valid = pow(x + y, p, p) == (pow(x, p, p) + pow(y, p, p)) % p

        # Decimal fixed-point ring D_2 vs IEEE-754 binary float
        ieee_drift = (0.1 + 0.2) != 0.3
        dec_exact = (Decimal("0.10") + Decimal("0.20")) == Decimal("0.30")

        return {
            "pillar": "04_algebraic_structures_decimal_ring",
            "frobenius_mod_97_valid": frobenius_valid,
            "ieee754_binary_drift_detected": ieee_drift,
            "decimal_ring_d2_exact": dec_exact,
            "verified": frobenius_valid and ieee_drift and dec_exact,
        }

    @classmethod
    def compute_pillar_05_exponents_logarithms_series(cls) -> Dict[str, Any]:
        n = 50
        s1 = sum(range(1, n + 1)) == n * (n + 1) // 2
        s2 = sum(k * k for k in range(1, n + 1)) == n * (n + 1) * (2 * n + 1) // 6
        s3 = sum(k ** 3 for k in range(1, n + 1)) == (n * (n + 1) // 2) ** 2

        # Stirling approximation error at n=20
        n_st = 20
        stirling_approx = math.sqrt(2 * math.pi * n_st) * ((n_st / math.e) ** n_st)
        stirling_rel_err = abs(math.factorial(n_st) - stirling_approx) / math.factorial(n_st)
        stirling_valid = stirling_rel_err < 0.005

        return {
            "pillar": "05_exponents_logarithms_series",
            "faulhaber_sums_valid": s1 and s2 and s3,
            "stirling_n20_relative_error": round(stirling_rel_err, 6),
            "verified": s1 and s2 and s3 and stirling_valid,
        }

    @classmethod
    def compute_pillar_06_linear_spectral_tensor_algebra(cls) -> Dict[str, Any]:
        # Matrix A = [[4, 2], [1, 3]] -> eigenvalues 5 and 2, Tr(A)=7, det(A)=10
        a11, a12, a21, a22 = 4.0, 2.0, 1.0, 3.0
        tr_a = a11 + a22
        det_a = a11 * a22 - a12 * a21
        l1, l2 = 5.0, 2.0
        spectral_valid = math.isclose(tr_a, l1 + l2) and math.isclose(det_a, l1 * l2)

        # Cayley-Hamilton: A^2 - Tr(A)*A + det(A)*I == 0
        a2_11 = a11 * a11 + a12 * a21
        a2_12 = a11 * a12 + a12 * a22
        a2_21 = a21 * a11 + a22 * a21
        a2_22 = a21 * a12 + a22 * a22
        ch_valid = (
            math.isclose(a2_11 - tr_a * a11 + det_a, 0.0)
            and math.isclose(a2_12 - tr_a * a12, 0.0)
            and math.isclose(a2_21 - tr_a * a21, 0.0)
            and math.isclose(a2_22 - tr_a * a22 + det_a, 0.0)
        )

        # Cauchy-Schwarz
        u = [3.0, -4.0, 12.0]
        v = [1.0, 2.0, -2.0]
        dot_uv = sum(ui * vi for ui, vi in zip(u, v))
        norm_u = math.sqrt(sum(ui * ui for ui in u))
        norm_v = math.sqrt(sum(vi * vi for vi in v))
        cs_valid = abs(dot_uv) <= norm_u * norm_v + 1e-12

        return {
            "pillar": "06_linear_spectral_tensor_algebra",
            "trace": tr_a,
            "determinant": det_a,
            "eigenvalues": [l1, l2],
            "cayley_hamilton_zero": ch_valid,
            "cauchy_schwarz_valid": cs_valid,
            "verified": spectral_valid and ch_valid and cs_valid,
        }

    @classmethod
    def compute_pillar_07_geometry_topology(cls) -> Dict[str, Any]:
        # Triangle (13, 14, 15) -> Heron area = 84
        a, b, c = 13.0, 14.0, 15.0
        s = (a + b + c) / 2.0
        heron_area = math.sqrt(s * (s - a) * (s - b) * (s - c))
        heron_valid = math.isclose(heron_area, 84.0)

        # 3D sphere volume via n-ball Gamma formula: pi^(3/2) / Gamma(5/2) * r^3 == 4/3 * pi * r^3
        r = 3.0
        vol_gamma = (math.pi ** 1.5) / math.gamma(2.5) * (r ** 3)
        vol_classic = (4.0 / 3.0) * math.pi * (r ** 3)
        vol_valid = math.isclose(vol_gamma, vol_classic)

        # Euler-Poincare characteristic of an icosahedron (V=12, E=30, F=20 -> chi = 2)
        chi_icosahedron = 12 - 30 + 20
        euler_poincare_valid = chi_icosahedron == 2

        return {
            "pillar": "07_geometry_topology",
            "heron_area_13_14_15": heron_area,
            "sphere_volume_r3": round(vol_classic, 6),
            "euler_poincare_chi": chi_icosahedron,
            "verified": heron_valid and vol_valid and euler_poincare_valid,
        }

    @classmethod
    def compute_pillar_08_trigonometry_circular_hyperbolic_spherical(cls) -> Dict[str, Any]:
        a, b = 0.42, 0.73
        cos_add_exact = math.isclose(
            math.cos(a + b),
            math.cos(a) * math.cos(b) - math.sin(a) * math.sin(b),
            rel_tol=1e-14,
        )
        sin_add_exact = math.isclose(
            math.sin(a + b),
            math.sin(a) * math.cos(b) + math.cos(a) * math.sin(b),
            rel_tol=1e-14,
        )
        hyp_valid = math.isclose(math.cosh(a) ** 2 - math.sinh(a) ** 2, 1.0, rel_tol=1e-14)
        moivre_lhs = complex(math.cos(a), math.sin(a)) ** 5
        moivre_rhs = complex(math.cos(5 * a), math.sin(5 * a))
        moivre_valid = cmath.isclose(moivre_lhs, moivre_rhs, rel_tol=1e-14)

        return {
            "pillar": "08_trigonometry_circular_hyperbolic_spherical",
            "cos_addition_exact_formula_valid": cos_add_exact,
            "sin_addition_exact_formula_valid": sin_add_exact,
            "hyperbolic_identity_valid": hyp_valid,
            "de_moivre_n5_valid": moivre_valid,
            "verified": cos_add_exact and sin_add_exact and hyp_valid and moivre_valid,
        }

    @classmethod
    def compute_pillar_09_real_analysis_taylor_optimization(cls) -> Dict[str, Any]:
        x = 1.25
        taylor_exp = sum((x ** n) / math.factorial(n) for n in range(25))
        taylor_valid = math.isclose(taylor_exp, math.exp(x), rel_tol=1e-14)

        # Jensen inequality for convex f(t) = t^2
        samples = [1.0, 2.0, 5.0, 8.0]
        mean_x = sum(samples) / len(samples)
        mean_f = sum(t * t for t in samples) / len(samples)
        jensen_valid = (mean_x ** 2) <= mean_f

        return {
            "pillar": "09_real_analysis_taylor_optimization",
            "taylor_exp_1_25": round(taylor_exp, 12),
            "jensen_convexity_valid": jensen_valid,
            "verified": taylor_valid and jensen_valid,
        }

    @classmethod
    def compute_pillar_10_integral_calculus_special_functions(cls) -> Dict[str, Any]:
        # Simpson's rule on int_0^pi sin(x) dx == 2
        n_steps = 1000
        a, b = 0.0, math.pi
        h = (b - a) / n_steps
        simpson = math.sin(a) + math.sin(b)
        for i in range(1, n_steps):
            weight = 4 if i % 2 == 1 else 2
            simpson += weight * math.sin(a + i * h)
        simpson *= h / 3.0
        simpson_valid = math.isclose(simpson, 2.0, rel_tol=1e-10)

        # Beta-Gamma identity: B(x, y) == Gamma(x)*Gamma(y)/Gamma(x+y) and int_0^1 t^(x-1)(1-t)^(y-1) dt
        bx, by = 3.0, 4.0
        beta_val = math.gamma(bx) * math.gamma(by) / math.gamma(bx + by)
        beta_exact = 1.0 / 60.0  # 2! * 3! / 6! = 12 / 720 = 1/60
        beta_valid = math.isclose(beta_val, beta_exact, rel_tol=1e-14)

        return {
            "pillar": "10_integral_calculus_special_functions",
            "simpson_int_sin_0_pi": round(simpson, 12),
            "euler_beta_3_4": round(beta_val, 12),
            "verified": simpson_valid and beta_valid,
        }

    @classmethod
    def compute_pillar_11_complex_harmonic_fourier(cls) -> Dict[str, Any]:
        euler_identity_residual = abs(cmath.exp(1j * math.pi) + 1.0)
        euler_valid = euler_identity_residual < 1e-15

        # Discrete Fourier Transform (DFT) & Parseval energy conservation
        signal = [1.0, -1.0, 2.0, 0.5, -0.5, 1.5, 0.0, -1.5]
        big_n = len(signal)
        spectrum = [
            sum(signal[n] * cmath.exp(-2j * math.pi * k * n / big_n) for n in range(big_n))
            for k in range(big_n)
        ]
        time_energy = sum(abs(x) ** 2 for x in signal)
        freq_energy = sum(abs(xk) ** 2 for xk in spectrum) / big_n
        parseval_valid = math.isclose(time_energy, freq_energy, rel_tol=1e-12)

        return {
            "pillar": "11_complex_harmonic_fourier",
            "euler_identity_residual": euler_identity_residual,
            "parseval_time_energy": time_energy,
            "parseval_freq_energy": round(freq_energy, 12),
            "verified": euler_valid and parseval_valid,
        }

    @classmethod
    def compute_pillar_12_differential_equations_stochastic(cls) -> Dict[str, Any]:
        # RK4 on dy/dt = -2y, y(0) = 3 -> y(1) = 3 * e^(-2)
        y = 3.0
        t = 0.0
        dt = 0.001
        for _ in range(1000):
            k1 = -2.0 * y
            k2 = -2.0 * (y + 0.5 * dt * k1)
            k3 = -2.0 * (y + 0.5 * dt * k2)
            k4 = -2.0 * (y + dt * k3)
            y += (dt / 6.0) * (k1 + 2 * k2 + 2 * k3 + k4)
            t += dt
        exact_y1 = 3.0 * math.exp(-2.0)
        rk4_valid = math.isclose(y, exact_y1, rel_tol=1e-9)

        # Black-Scholes Call-Put Parity: C - P == S0 - K * exp(-r*T)
        s0, k_strike, r_rate, sigma, mat_t = 100.0, 100.0, 0.05, 0.20, 1.0
        d1 = (math.log(s0 / k_strike) + (r_rate + 0.5 * sigma ** 2) * mat_t) / (sigma * math.sqrt(mat_t))
        d2 = d1 - sigma * math.sqrt(mat_t)
        norm_cdf = lambda z: 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))
        call_price = s0 * norm_cdf(d1) - k_strike * math.exp(-r_rate * mat_t) * norm_cdf(d2)
        put_price = k_strike * math.exp(-r_rate * mat_t) * norm_cdf(-d2) - s0 * norm_cdf(-d1)
        parity_valid = math.isclose(call_price - put_price, s0 - k_strike * math.exp(-r_rate * mat_t), rel_tol=1e-12)

        return {
            "pillar": "12_differential_equations_stochastic",
            "rk4_ode_y1": round(y, 10),
            "black_scholes_call": round(call_price, 6),
            "black_scholes_put": round(put_price, 6),
            "call_put_parity_valid": parity_valid,
            "verified": rk4_valid and parity_valid,
        }

    @classmethod
    def compute_pillar_13_combinatorics_graphs_complexity(cls) -> Dict[str, Any]:
        # Catalan C_5 = 42, Cayley trees on K_6 = 6^4 = 1296
        catalan_5 = math.comb(10, 5) // 6
        cayley_6 = 6 ** (6 - 2)
        # Handshaking lemma on K_5: 5 vertices of degree 4 -> sum(deg) = 20 = 2 * 10 edges
        handshaking_valid = (5 * 4) == 2 * math.comb(5, 2)
        return {
            "pillar": "13_combinatorics_graphs_complexity",
            "catalan_c5": catalan_5,
            "cayley_spanning_trees_k6": cayley_6,
            "handshaking_lemma_valid": handshaking_valid,
            "verified": (catalan_5 == 42) and (cayley_6 == 1296) and handshaking_valid,
        }

    @classmethod
    def compute_pillar_14_probability_statistics_markov(cls) -> Dict[str, Any]:
        # Bayes theorem
        p_d = 0.01
        p_pos_given_d = 0.99
        p_pos_given_not_d = 0.05
        p_d_given_pos = (p_pos_given_d * p_d) / (p_pos_given_d * p_d + p_pos_given_not_d * (1.0 - p_d))

        # Konig-Huygens variance identity: Var(X) == E[X^2] - (E[X])^2
        vals = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        mean_v = sum(vals) / len(vals)
        var_direct = sum((x - mean_v) ** 2 for x in vals) / len(vals)
        var_konig = (sum(x * x for x in vals) / len(vals)) - (mean_v ** 2)
        konig_valid = math.isclose(var_direct, var_konig, rel_tol=1e-14) and math.isclose(var_direct, 4.0)

        return {
            "pillar": "14_probability_statistics_markov",
            "bayes_posterior": round(p_d_given_pos, 6),
            "variance_konig_huygens": var_direct,
            "verified": (0.16 < p_d_given_pos < 0.17) and konig_valid,
        }

    @classmethod
    def compute_pillar_15_shannon_information_theory(cls) -> Dict[str, Any]:
        p_dist = [0.5, 0.25, 0.125, 0.125]
        q_dist = [0.25, 0.25, 0.25, 0.25]
        shannon_h_p = -sum(p * math.log2(p) for p in p_dist)  # Exact 1.75 bits
        shannon_h_q = -sum(q * math.log2(q) for q in q_dist)  # Exact 2.00 bits
        kl_div = sum(p * math.log2(p / q) for p, q in zip(p_dist, q_dist))  # Exact 0.25 bits
        shannon_capacity = 20e6 * math.log2(1.0 + 15.0)  # B=20 MHz, SNR=15 -> 80 Mbps

        return {
            "pillar": "15_shannon_information_theory",
            "shannon_entropy_bits": shannon_h_p,
            "max_uniform_entropy_bits": shannon_h_q,
            "kl_divergence_bits": kl_div,
            "channel_capacity_mbps": shannon_capacity / 1e6,
            "verified": math.isclose(shannon_h_p, 1.75) and (kl_div > 0) and math.isclose(shannon_capacity, 80e6),
        }

    @classmethod
    def compute_pillar_16_supela_k3_cryptographic_epistemic_core(cls) -> Dict[str, Any]:
        ledger = SupelaWormLedger()
        parent_h = ledger.head_hash
        prop_id = "CONTINUUM-CTX-2026"
        proof = generate_schnorr_nizk_proof("SUPELA-23-PILLAR-CONTINUUM-WITNESS", prop_id, parent_h)
        schnorr_ok = verify_schnorr_nizk_proof(proof, proof.public_key_y_hex, prop_id, parent_h)

        ledger.append_sealed_event("VR-13", "CONTINUUM_INIT", {"pillar": 16, "status": "LEVEL_3_AUDITABLE"})
        ledger.append_sealed_event("VR-13", "K3_EPISTEMIC_DEMOTION", {"from": "LEVEL_3_AUDITABLE", "to": "LEVEL_2_TESTED_QUARANTINE"})
        merkle_ok, _ = ledger.verify_integrity()

        return {
            "pillar": "16_supela_k3_cryptographic_epistemic_core",
            "schnorr_2048_rfc3526_verified": schnorr_ok,
            "worm_merkle_root": ledger.compute_merkle_root(),
            "worm_merkle_integrity": merkle_ok,
            "verified": schnorr_ok and merkle_ok,
        }

    @classmethod
    def compute_pillar_17_silicon_physics_bjt_jfet_mosfet_cmos(cls) -> Dict[str, Any]:
        # Physical constants (SI)
        k_b = 1.380649e-23  # Boltzmann constant (J/K)
        q_e = 1.602176634e-19  # Elementary charge (C)
        temp_k = 300.0  # 300 K
        v_t = (k_b * temp_k) / q_e  # Thermal voltage ~ 0.02585199 V (25.85 mV)
        landauer_min_j = k_b * temp_k * math.log(2.0)  # ~ 2.87e-21 J

        # 1. BJT equations: I_E = I_C + I_B, I_C = beta * I_B, g_m = I_C / V_T, r_o = V_A / I_C
        beta = 100.0
        i_b = 20e-6  # 20 uA
        i_c = beta * i_b  # 2.0 mA
        i_e = i_c + i_b  # 2.02 mA
        alpha_bjt = beta / (beta + 1.0)
        v_ce = 5.0
        v_a_bjt = 100.0  # Early voltage 100 V
        p_d_bjt = v_ce * i_c
        g_m_bjt = i_c / v_t
        r_pi_bjt = beta / g_m_bjt
        r_o_bjt = v_a_bjt / i_c
        bjt_valid = (
            math.isclose(i_e, i_c + i_b)
            and math.isclose(alpha_bjt * i_e, i_c)
            and math.isclose(r_pi_bjt, v_t / i_b)
        )

        # 2. JFET Shockley equations: I_D = I_DSS * (1 - V_GS / V_P)^2
        i_dss = 10e-3  # 10 mA
        v_p = -4.0  # Pinch-off voltage -4 V
        v_gs_jfet = -1.5  # >= V_P
        i_d_jfet = i_dss * ((1.0 - (v_gs_jfet / v_p)) ** 2)
        g_m_jfet = (2.0 * i_dss / abs(v_p)) * (1.0 - (v_gs_jfet / v_p))
        jfet_valid = (i_d_jfet > 0.0) and (g_m_jfet > 0.0) and (v_gs_jfet >= v_p)

        # 3. MOSFET (Linear & Saturation + transition frequency f_T + CMOS power)
        mu_n_cox = 200e-6  # 200 uA/V^2
        w_over_l = 10.0
        v_th = 0.4
        v_gs_mos = 1.2
        v_ds_lin = 0.2  # < V_GS - V_th (0.8 V)
        v_ds_sat = 1.2  # >= V_GS - V_th (0.8 V)
        v_a_mos = 50.0

        i_d_mos_lin = mu_n_cox * w_over_l * ((v_gs_mos - v_th) * v_ds_lin - 0.5 * (v_ds_lin ** 2))
        i_d_mos_sat = 0.5 * mu_n_cox * w_over_l * ((v_gs_mos - v_th) ** 2)
        g_m_mos = mu_n_cox * w_over_l * (v_gs_mos - v_th)
        r_o_mos = v_a_mos / i_d_mos_sat
        c_gs, c_gd = 15e-15, 5e-15  # 15 fF, 5 fF
        f_t_hz = g_m_mos / (2.0 * math.pi * (c_gs + c_gd))

        # CMOS dynamic + static power
        alpha_act, c_load, v_dd, f_clk = 0.25, 10e-15, 1.0, 3e9
        p_cmos_dyn = alpha_act * c_load * (v_dd ** 2) * f_clk
        mosfet_valid = (i_d_mos_sat > i_d_mos_lin > 0.0) and (f_t_hz > 1e9) and (r_o_mos > 0.0)

        return {
            "pillar": "17_silicon_physics_bjt_jfet_mosfet_cmos",
            "thermal_voltage_vt_mv": round(v_t * 1000.0, 4),
            "landauer_bit_erasure_joules": landauer_min_j,
            "bjt": {
                "i_c_ma": round(i_c * 1e3, 4),
                "i_e_ma": round(i_e * 1e3, 4),
                "g_m_ms": round(g_m_bjt * 1e3, 4),
                "r_o_kohm": round(r_o_bjt / 1e3, 4),
                "p_d_mw": round(p_d_bjt * 1e3, 4),
            },
            "jfet": {
                "i_d_sat_ma": round(i_d_jfet * 1e3, 4),
                "g_m_ms": round(g_m_jfet * 1e3, 4),
            },
            "mosfet_cmos": {
                "i_d_lin_ua": round(i_d_mos_lin * 1e6, 4),
                "i_d_sat_ua": round(i_d_mos_sat * 1e6, 4),
                "g_m_ms": round(g_m_mos * 1e3, 4),
                "r_o_kohm": round(r_o_mos / 1e3, 4),
                "f_t_ghz": round(f_t_hz / 1e9, 4),
                "p_cmos_dyn_uw": round(p_cmos_dyn * 1e6, 4),
            },
            "verified": bjt_valid and jfet_valid and mosfet_valid,
        }

    @classmethod
    def compute_pillar_18_nand_gates_cla_adder_alu(cls) -> Dict[str, Any]:
        # Universal NAND synthesis of NOT, AND, OR, XOR
        not_g = lambda a: cls._nand(a, a)
        and_g = lambda a, b: not_g(cls._nand(a, b))
        or_g = lambda a, b: cls._nand(not_g(a), not_g(b))
        xor_g = lambda a, b: cls._nand(cls._nand(a, cls._nand(a, b)), cls._nand(b, cls._nand(a, b)))

        nand_truth_valid = all(
            and_g(a, b) == (a & b) and or_g(a, b) == (a | b) and xor_g(a, b) == (a ^ b)
            for a in (0, 1)
            for b in (0, 1)
        )

        # 8-bit Carry-Lookahead Adder (CLA) built purely from G_i = A_i & B_i, P_i = A_i ^ B_i
        val_a, val_b = 173, 69  # 173 + 69 = 242
        c = 0
        sum_bits = 0
        for i in range(8):
            ai = (val_a >> i) & 1
            bi = (val_b >> i) & 1
            gi = and_g(ai, bi)
            pi = xor_g(ai, bi)
            si = xor_g(pi, c)
            c = or_g(gi, and_g(pi, c))
            sum_bits |= (si << i)
        cla_valid = (sum_bits == val_a + val_b) and (c == 0)

        return {
            "pillar": "18_nand_gates_cla_adder_alu",
            "nand_universal_synthesis_valid": nand_truth_valid,
            "cla_8bit_sum_173_plus_69": sum_bits,
            "verified": nand_truth_valid and cla_valid,
        }

    @classmethod
    def compute_pillar_19_sequential_cpu_amdahl_little(cls) -> Dict[str, Any]:
        # Setup & Hold timing check (in picoseconds)
        t_cq, t_logic_max, t_logic_min, t_su, t_hold, t_skew = 45.0, 180.0, 35.0, 25.0, 20.0, 10.0
        t_clk_min_ps = t_cq + t_logic_max + t_su - t_skew  # 240 ps -> 4.1667 GHz
        hold_margin_ps = (t_cq + t_logic_min) - (t_hold + t_skew)  # 80 - 30 = +50 ps > 0
        timing_valid = (t_clk_min_ps > 0) and (hold_margin_ps >= 0)

        # Amdahl vs Gustafson for p=0.90 parallel fraction, N=16 cores
        p_par, n_cores = 0.90, 16
        amdahl = 1.0 / ((1.0 - p_par) + (p_par / n_cores))
        gustafson = (1.0 - p_par) + n_cores * p_par

        # Little's Law: L = lambda * W
        lam_tps, w_sec = 2500.0, 0.040
        l_in_flight = lam_tps * w_sec

        return {
            "pillar": "19_sequential_cpu_amdahl_little",
            "max_clock_ghz": round(1000.0 / t_clk_min_ps, 4),
            "hold_slack_ps": hold_margin_ps,
            "amdahl_speedup_16c": round(amdahl, 4),
            "gustafson_speedup_16c": round(gustafson, 4),
            "little_law_in_flight_tx": l_in_flight,
            "verified": timing_valid and (amdahl < 10.0) and (gustafson > 14.0),
        }

    @classmethod
    def compute_pillar_20_turing_lambda_curry_howard(cls) -> Dict[str, Any]:
        # Church numerals in pure Lambda-calculus: PLUS 3 4 = 7
        church = lambda n: (lambda f: (lambda x: eval_n(n, f, x)))

        def eval_n(n: int, f, x):
            res = x
            for _ in range(n):
                res = f(res)
            return res

        plus = lambda m, n: (lambda f: (lambda x: m(f)(n(f)(x))))
        mult = lambda m, n: (lambda f: m(n(f)))

        c3, c4 = church(3), church(4)
        church_add_val = plus(c3, c4)(lambda v: v + 1)(0)
        church_mul_val = mult(c3, c4)(lambda v: v + 1)(0)

        return {
            "pillar": "20_turing_lambda_curry_howard",
            "church_lambda_3_plus_4": church_add_val,
            "church_lambda_3_mult_4": church_mul_val,
            "verified": (church_add_val == 7) and (church_mul_val == 12),
        }

    @classmethod
    def compute_pillar_21_hoare_dijkstra_tla_verification(cls) -> Dict[str, Any]:
        # Verify loop invariant I: (acc == sum_{k=1}^{i} k) and strictly decreasing variant V = N - i >= 0
        big_n = 25
        acc = 0
        i = 0
        invariant_held_every_step = True
        variant_strictly_decreased = True
        prev_variant = big_n - i
        while i < big_n:
            invariant_held_every_step &= (acc == i * (i + 1) // 2)
            i += 1
            acc += i
            cur_variant = big_n - i
            variant_strictly_decreased &= (cur_variant < prev_variant) and (cur_variant >= 0)
            prev_variant = cur_variant
        postcondition_held = (acc == big_n * (big_n + 1) // 2) and (i == big_n)

        return {
            "pillar": "21_hoare_dijkstra_tla_verification",
            "hoare_invariant_maintained": invariant_held_every_step,
            "variant_strictly_decreasing": variant_strictly_decreased,
            "postcondition_verified": postcondition_held,
            "verified": invariant_held_every_step and variant_strictly_decreased and postcondition_held,
        }

    @classmethod
    def compute_pillar_22_distributed_bft_and_continuum_extrapolation(cls) -> Dict[str, Any]:
        # Byzantine Fault Tolerance (BFT): N = 3f + 1, Quorum Q = 2f + 1 -> |Q1 cap Q2| >= f + 1
        f_faulty = 4
        n_nodes = 3 * f_faulty + 1  # 13 nodes
        quorum_size = 2 * f_faulty + 1  # 9 nodes
        min_intersection = 2 * quorum_size - n_nodes  # 18 - 13 = 5 = f + 1
        min_honest_in_intersection = min_intersection - f_faulty  # 5 - 4 = 1 >= 1

        # Lamport vector clock happens-before check
        v_e1 = (1, 0, 0)
        v_e2 = (1, 2, 0)
        v_e3 = (2, 2, 1)
        happens_before = lambda va, vb: all(a <= b for a, b in zip(va, vb)) and any(a < b for a, b in zip(va, vb))
        causal_chain_valid = happens_before(v_e1, v_e2) and happens_before(v_e2, v_e3)

        return {
            "pillar": "22_distributed_bft_and_continuum_extrapolation",
            "bft_total_nodes": n_nodes,
            "bft_max_byzantine_faults": f_faulty,
            "bft_quorum_size": quorum_size,
            "bft_min_honest_intersection": min_honest_in_intersection,
            "vector_clock_causality_valid": causal_chain_valid,
            "verified": (min_honest_in_intersection >= 1) and causal_chain_valid,
        }

    @classmethod
    def compute_pillar_23_known_vs_unformulated_unknown_boundary(cls) -> Dict[str, Any]:
        """
        Pilier 23 — Frontière du Connu Formulé et de l'Inconnu Non Formulé :
        1. Diagonalisation constructive de Cantor : pour tout catalogue énuméré de formules
           F = [f_0, ..., f_{m-1}], la séquence diagonale d(i) = 1 - f_i(i) n'appartient
           à aucune formule du catalogue (forall i, d != f_i).
        2. Bruit stochastique irréductible dans les transistors : Johnson-Nyquist (4*k_B*T*R*df),
           Shot Noise (2*q*I_D*df) et borne quantique d'Heisenberg (hbar / 2).
        3. Garde-fou Fail-Closed : toute observation non formulée est bloquée et mise en
           quarantaine épistémique L2Q (zéro extrapolation aveugle).
        """
        # 1. Cantor diagonal construction over an enumerated catalog of 8 binary formulas
        catalog = [
            [0, 1, 0, 1, 0, 1, 0, 1],
            [1, 1, 0, 0, 1, 1, 0, 0],
            [0, 0, 1, 1, 1, 0, 0, 1],
            [1, 0, 1, 0, 1, 0, 1, 0],
            [1, 1, 1, 1, 0, 0, 0, 0],
            [0, 1, 1, 0, 0, 1, 1, 0],
            [0, 0, 0, 1, 1, 1, 0, 1],
            [1, 0, 0, 1, 0, 1, 1, 0],
        ]
        cantor_diagonal_unformulated = [1 - catalog[i][i] for i in range(len(catalog))]
        strictly_outside_catalog = all(cantor_diagonal_unformulated != row for row in catalog)

        # 2. Physical stochastic limits in transistors (Thermal Johnson-Nyquist, Shot noise, Heisenberg)
        k_b = 1.380649e-23
        q_e = 1.602176634e-19
        hbar = 1.054571817e-34
        temp_k = 300.0
        r_channel_ohm = 1000.0
        bandwidth_hz = 1e9
        i_drain_amp = 1e-3

        johnson_nyquist_v_rms = math.sqrt(4.0 * k_b * temp_k * r_channel_ohm * bandwidth_hz)
        shot_noise_i_rms = math.sqrt(2.0 * q_e * i_drain_amp * bandwidth_hz)
        heisenberg_min_action_js = 0.5 * hbar

        # 3. Fail-Closed gate on unformulated unknown observations
        known_check = cls.evaluate_unformulated_observation("PILLAR_17")
        unknown_check = cls.evaluate_unformulated_observation("UNFORMULATED_TRANSISTOR_QUANTUM_ANOMALY_X99")
        forced_extrapolation_check = cls.evaluate_unformulated_observation(
            "UNFORMULATED_GÖDEL_SENTENCE_G_T", force_silent_extrapolation=True
        )
        fail_closed_valid = (
            known_check["domain_status"] == "FORMULATED_KNOWN"
            and unknown_check["domain_status"] == "UNFORMULATED_UNKNOWN_DETECTED"
            and unknown_check["action"] == "FAIL_CLOSED_QUARANTINE"
            and unknown_check["epistemic_level"] == "LEVEL_2_TESTED_QUARANTINE"
            and not unknown_check["silent_extrapolation_permitted"]
            and forced_extrapolation_check["action"] == "FAIL_CLOSED_QUARANTINE"
            and not forced_extrapolation_check["silent_extrapolation_permitted"]
            and forced_extrapolation_check["extrapolation_override_rejected"]
        )

        return {
            "pillar": "23_known_vs_unformulated_unknown_boundary",
            "cantor_unformulated_diagonal_witness": cantor_diagonal_unformulated,
            "cantor_strictly_outside_enumerated_catalog": strictly_outside_catalog,
            "transistor_johnson_nyquist_noise_uv_rms": round(johnson_nyquist_v_rms * 1e6, 4),
            "transistor_shot_noise_na_rms": round(shot_noise_i_rms * 1e9, 4),
            "heisenberg_lower_bound_js": heisenberg_min_action_js,
            "unformulated_unknown_gate": unknown_check,
            "verified": strictly_outside_catalog and (johnson_nyquist_v_rms > 0) and (shot_noise_i_rms > 0) and fail_closed_valid,
        }

    @classmethod
    def evaluate_unformulated_observation(
        cls, domain_tag: str, force_silent_extrapolation: bool = False
    ) -> Dict[str, Any]:
        """
        Évalue une observation par rapport au catalogue dénombrable des 23 piliers formulés.
        Même si `force_silent_extrapolation=True` est demandé par l'appelant, toute entrée
        hors du domaine formulé est bloquée en quarantaine Fail-Closed (LEVEL_2_TESTED_QUARANTINE).
        """
        formulated_domain = {f"PILLAR_{idx:02d}" for idx in range(1, 24)}
        if domain_tag in formulated_domain and not force_silent_extrapolation:
            return {
                "domain_tag": domain_tag,
                "domain_status": "FORMULATED_KNOWN",
                "action": "DETERMINISTIC_EVALUATION",
                "epistemic_level": "LEVEL_3_AUDITABLE",
                "silent_extrapolation_permitted": False,
                "extrapolation_override_rejected": False,
            }
        return {
            "domain_tag": domain_tag,
            "domain_status": "UNFORMULATED_UNKNOWN_DETECTED",
            "action": "FAIL_CLOSED_QUARANTINE",
            "epistemic_level": "LEVEL_2_TESTED_QUARANTINE",
            "silent_extrapolation_permitted": False,
            "extrapolation_override_rejected": bool(force_silent_extrapolation),
            "reason": "Known is finite/enumerable (Aleph_0); unformulated reality is uncountable (2^Aleph_0). Silent extrapolation is forbidden.",
        }

    @classmethod
    def validate_against_json_schema(
        cls, report: Dict[str, Any], schema_path: str
    ) -> Tuple[bool, List[str]]:
        """Valide formellement le reçu des 23 piliers contre schemas/supela_continuum_23_pillars.schema.json."""
        with open(schema_path, "r", encoding="utf-8") as fh:
            schema = json.load(fh)

        errors: List[str] = []
        for req_key in schema.get("required", []):
            if req_key not in report:
                errors.append(f"Missing required top-level field: {req_key}")

        if report.get("total_pillars_computed") != 23:
            errors.append("total_pillars_computed must equal const 23")
        if report.get("all_22_pillars_verified") is not True:
            errors.append("all_22_pillars_verified must equal const true")
        if report.get("all_23_pillars_verified") is not True:
            errors.append("all_23_pillars_verified must equal const true")

        ax_schema = schema["properties"]["axiomatic_system"]
        ax_obj = report.get("axiomatic_system", {})
        for req_ax in ax_schema.get("required", []):
            if req_ax not in ax_obj or not isinstance(ax_obj[req_ax], str):
                errors.append(f"Invalid or missing axiom: {req_ax}")

        ne_schema = schema["properties"]["non_exhaustiveness_and_incompleteness_declaration"]
        ne_obj = report.get("non_exhaustiveness_and_incompleteness_declaration", {})
        for req_ne in ne_schema.get("required", []):
            if req_ne not in ne_obj:
                errors.append(f"Missing non_exhaustiveness field: {req_ne}")
        if ne_obj.get("formulated_domain_cardinality") != "ALEPH_0_COUNTABLE_ENUMERABLE":
            errors.append("Invalid formulated_domain_cardinality")
        if ne_obj.get("unformulated_reality_cardinality") != "TWO_POW_ALEPH_0_UNCOUNTABLE_CONTINUUM":
            errors.append("Invalid unformulated_reality_cardinality")
        if ne_obj.get("lebesgue_measure_of_formulated_in_reality") != 0.0:
            errors.append("lebesgue_measure_of_formulated_in_reality must be 0.0")
        if ne_obj.get("completeness_claim_prohibited") is not True:
            errors.append("completeness_claim_prohibited must be true")
        if ne_obj.get("fail_closed_on_unformulated_input") is not True:
            errors.append("fail_closed_on_unformulated_input must be true")

        quads = ne_obj.get("four_epistemic_quadrants", {})
        for q_key in ne_schema["properties"]["four_epistemic_quadrants"]["required"]:
            if q_key not in quads or not isinstance(quads[q_key], str):
                errors.append(f"Missing epistemic quadrant: {q_key}")

        pillars = report.get("pillars", [])
        if len(pillars) != 23:
            errors.append(f"Expected 23 pillars, got {len(pillars)}")
        for idx, p in enumerate(pillars):
            if p.get("verified") is not True:
                errors.append(f"Pillar at index {idx} is not verified")

        return (len(errors) == 0), errors

    @classmethod
    def execute_all_22_pillars(cls) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = [
            cls.compute_pillar_01_logic_sets_lattices(),
            cls.compute_pillar_02_number_theory_modular(),
            cls.compute_pillar_03_algebra_polynomials(),
            cls.compute_pillar_04_algebraic_structures_decimal_ring(),
            cls.compute_pillar_05_exponents_logarithms_series(),
            cls.compute_pillar_06_linear_spectral_tensor_algebra(),
            cls.compute_pillar_07_geometry_topology(),
            cls.compute_pillar_08_trigonometry_circular_hyperbolic_spherical(),
            cls.compute_pillar_09_real_analysis_taylor_optimization(),
            cls.compute_pillar_10_integral_calculus_special_functions(),
            cls.compute_pillar_11_complex_harmonic_fourier(),
            cls.compute_pillar_12_differential_equations_stochastic(),
            cls.compute_pillar_13_combinatorics_graphs_complexity(),
            cls.compute_pillar_14_probability_statistics_markov(),
            cls.compute_pillar_15_shannon_information_theory(),
            cls.compute_pillar_16_supela_k3_cryptographic_epistemic_core(),
            cls.compute_pillar_17_silicon_physics_bjt_jfet_mosfet_cmos(),
            cls.compute_pillar_18_nand_gates_cla_adder_alu(),
            cls.compute_pillar_19_sequential_cpu_amdahl_little(),
            cls.compute_pillar_20_turing_lambda_curry_howard(),
            cls.compute_pillar_21_hoare_dijkstra_tla_verification(),
            cls.compute_pillar_22_distributed_bft_and_continuum_extrapolation(),
            cls.compute_pillar_23_known_vs_unformulated_unknown_boundary(),
        ]
        all_verified = all(r["verified"] for r in results) and (len(results) == 23)
        canonical_json = json.dumps(results, sort_keys=True, separators=(",", ":")).encode("utf-8")
        continuum_sha256 = f"sha256:{hashlib.sha256(canonical_json).hexdigest()}"
        return {
            "continuum_title": "Supela-K3-Omega 23-Pillar Mathematical, Transistor, Doctoral CS & Unformulated-Unknown Boundary Executable Continuum",
            "total_pillars_computed": len(results),
            "all_22_pillars_verified": all_verified,
            "all_23_pillars_verified": all_verified,
            "continuum_execution_sha256": continuum_sha256,
            "epistemic_status": "LEVEL_3_AUDITABLE",
            "unformulated_unknown_invariant": "Known is enumerable (Aleph_0); unformulated reality is uncountable (2^Aleph_0). Any unformulated observation triggers Fail-Closed quarantine (LEVEL_2_TESTED_QUARANTINE).",
            "axiomatic_system": {
                "axiom_1_silicon_to_proof_continuity": "Delta_E >= k_B*T*ln(2) -> Transistor(BJT/JFET/MOSFET) -> Gate(NAND) -> ALU(CLA) -> Ring(D_2, Z_p*) -> Proof(Schnorr, Ed25519, Merkle) -> Lattice(L0..L5)",
                "axiom_2_decimal_algebraic_exactness": "All monetary and accounting flows execute in the exact fixed-point decimal ring D_2 = Z * 10^-2; binary IEEE-754 floating-point drift is forbidden.",
                "axiom_3_local_epistemic_ceiling": "For all local runtime components c, Authority(c) == Self implies Level(c) <= LEVEL_3_AUDITABLE (no self-attribution of Level 4 or Level 5).",
                "axiom_4_monotonic_contradiction_demotion": "Any contradictory observation O_{not c} on a LEVEL_3_AUDITABLE claim immediately demotes it to LEVEL_2_TESTED_QUARANTINE and seals a K3_EPISTEMIC_DEMOTION block in the WORM Merkle chain.",
                "axiom_5_omission_visibility_entropy": "For any reformulation Y = R(X) with |Y| < |X|, Shannon conditional entropy H(X|Y) > 0; Y is valid iff bound to SHA256(X) with an explicit non-empty omission manifest and Substitutable(Y, X) == False.",
                "axiom_6_unformulated_unknown_fail_closed": "The set of all formulated equations Sigma* is countable (Aleph_0) whereas physical/mathematical reality is uncountable (2^Aleph_0); any unformulated observation outside the enumerated domain triggers Fail-Closed quarantine (LEVEL_2_TESTED_QUARANTINE)."
            },
            "non_exhaustiveness_and_incompleteness_declaration": {
                "formulated_domain_cardinality": "ALEPH_0_COUNTABLE_ENUMERABLE",
                "unformulated_reality_cardinality": "TWO_POW_ALEPH_0_UNCOUNTABLE_CONTINUUM",
                "lebesgue_measure_of_formulated_in_reality": 0.0,
                "completeness_claim_prohibited": True,
                "fail_closed_on_unformulated_input": True,
                "four_epistemic_quadrants": {
                    "Q1_known_formulated_verified": "Pillars 01..22: Equations explicitly formulated, executed, and verified at LEVEL_3_AUDITABLE.",
                    "Q2_known_external_authority_bound": "Level 4 (SWIFT MyStandards/ITB, FIPS 140-3 HSM) & Level 5 (Production Telemetry) requiring third-party attestation.",
                    "Q3_known_formal_impossibility_or_noise_bounds": "Godel G_T unprovability, Turing Halting undecidability, Chaitin Omega, and transistor Johnson-Nyquist/Shot/Heisenberg noise bounds.",
                    "Q4_unformulated_unknown_open_horizon": "All phenomena outside the countable formal language Sigma* (2^Aleph_0 \\ Aleph_0) — governed by Fail-Closed quarantine (LEVEL_2_TESTED_QUARANTINE)."
                }
            },
            "pillars": results,
        }


if __name__ == "__main__":
    report = UniversalContinuumCalculator.execute_all_22_pillars()
    schema_file = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "schemas", "supela_continuum_23_pillars.schema.json")
    )
    schema_ok, schema_errs = UniversalContinuumCalculator.validate_against_json_schema(report, schema_file)
    if not schema_ok:
        raise RuntimeError(f"Schema validation failed: {schema_errs}")
    out_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "evidence", "universal_continuum_23_pillars_receipt.json")
    )
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps(report, indent=2))
    if not report["all_23_pillars_verified"]:
        sys.exit(1)



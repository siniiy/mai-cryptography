#!/usr/bin/env python3
"""
RSA Demo Script - Lab Work #2

Demonstrates:
1. Math Service (Legendre/Jacobi symbols, GCD, Extended GCD, Modular exponentiation)
2. Probabilistic primality tests (Fermat, Solovay-Strassen, Miller-Rabin)
3. RSA encryption/decryption service with nested key generator
4. Wiener attack service

Based on FIPS 186-5 specification and reference C++ implementation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cryptography.math_service import MathService
from src.cryptography.primality_tests import FermatTest, SolovayStrassenTest, MillerRabinTest
from src.cryptography.rsa_service import RSAService, RSAKeyPair
from src.cryptography.wiener_attack import WienerAttackService, WienerAttackResult


class Demonstration:
    @staticmethod
    def run():
        Demonstration.demonstrate_math_service()
        Demonstration.demonstrate_primality_tests()
        Demonstration.demonstrate_rsa()
        Demonstration.demonstrate_wiener_attack()
    
    @staticmethod
    def demonstrate_math_service():
        print("1. MATH SERVICE:")
        
        math_service = MathService()
        
        print(f"GCD(48, 18) = {math_service.gcd(48, 18)}")
        print(f"GCD(17, 13) = {math_service.gcd(17, 13)}")
        
        gcd_val, x, y = math_service.extended_gcd(48, 18)
        print(f"Extended GCD(48, 18): GCD={gcd_val}, x={x}, y={y}")
        
        print(f"2^10 mod 13 = {math_service.mod_exp(2, 10, 13)}")
        print(f"Legendre symbol (5/11) = {math_service.legendre_symbol(5, 11)}")
        print(f"Jacobi symbol (15, 11) = {math_service.jacobi_symbol(15, 11)}")
        
        print()
    
    @staticmethod
    def demonstrate_primality_tests():
        print("2. PRIMALITY TESTS:")
        
        math_service = MathService()
        test_numbers = [17, 19, 21, 23, 561, 7919]
        
        tests = [
            ("Fermat", FermatTest(math_service)),
            ("Solovay-Strassen", SolovayStrassenTest(math_service)),
            ("Miller-Rabin", MillerRabinTest(math_service))
        ]
        
        for name, test in tests:
            print(f"\n{name}:")
            for num in test_numbers:
                result = test.is_probably_prime(num, 0.8)
                print(f"  {num}: {'prime' if result else 'composite'}")
        print()
    
    @staticmethod
    def demonstrate_rsa():
        print("3. RSA ENCRYPTION:")
        print("Generating RSA keys...")
        
        try:
            rsa_service = RSAService(
                RSAService.PrimalityTestType.MILLER_RABIN,
                0.5,
                1024
            )
            
            key_pair = rsa_service.get_current_key_pair()
            
            print(f"\nPublic key: n={key_pair.public_key[0]}, e={key_pair.public_key[1]}")
            print(f"Private key: n={key_pair.private_key[0]}, d={key_pair.private_key[1]}")
            
            original_message = 42
            print(f"\nOriginal message: {original_message}")
            
            if original_message >= key_pair.public_key[0]:
                print("Message too large for key. Reducing...")
                original_message = key_pair.public_key[0] // 2
                print(f"New message: {original_message}")
            
            encrypted = rsa_service.encrypt(original_message, key_pair.public_key)
            print(f"Encrypted message: {encrypted}")
            
            decrypted = rsa_service.decrypt(encrypted, key_pair.private_key)
            print(f"Decrypted message: {decrypted}")
            
            print(f"\nMessage correctly recovered: {'YES' if original_message == decrypted else 'NO'}")
            
        except Exception as e:
            print(f"Error during RSA: {e}")
            print("Trying alternative approach...")
            Demonstration.demonstrate_simple_rsa()
    
    @staticmethod
    def mod_inverse(a: int, m: int, math_service: MathService) -> int:
        gcd_val, x, _ = math_service.extended_gcd(a, m)
        
        if gcd_val != 1:
            raise RuntimeError(f"Inverse does not exist. GCD = {gcd_val}")
        
        x = x % m
        if x < 0:
            x += m
        return x
    
    @staticmethod
    def demonstrate_simple_rsa():
        print("\n--- ALTERNATIVE RSA DEMONSTRATION ---")
        
        p = 61
        q = 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17
        d = 2753
        
        print("Using pre-computed parameters:")
        print(f"p = {p}, q = {q}")
        print(f"n = p * q = {n}")
        print(f"phi = (p-1)*(q-1) = {phi}")
        print(f"e = {e}")
        print(f"d = {d}")
        
        math_service = MathService()
        
        print("\nVerifying correctness:")
        print(f"GCD(e, phi) = {math_service.gcd(e, phi)} (should be 1)")
        print(f"e * d mod phi = {(e * d) % phi} (should be 1)")
        
        message = 42
        print(f"\nOriginal message: {message}")
        
        encrypted = math_service.mod_exp(message, e, n)
        print(f"Encrypted: {encrypted}")
        
        decrypted = math_service.mod_exp(encrypted, d, n)
        print(f"Decrypted: {decrypted}")
        
        print(f"Correctness: {'YES' if message == decrypted else 'NO'}")
    
    @staticmethod
    def demonstrate_wiener_attack():
        print("\n4. WIENER ATTACK ON RSA:")
        print("Wiener attack works when d < n^0.25")
        print("For successful attack, small secret exponents d are needed\n")
        
        math_service = MathService()
        wiener_service = WienerAttackService(math_service)
        
        print("=" * 70)
        print("EXAMPLE 1: VULNERABLE KEY WITH SMALL d")
        print("=" * 70)
        
        p1 = 101
        q1 = 113
        n1 = p1 * q1
        phi1 = (p1 - 1) * (q1 - 1)
        d1 = 3
        
        e1 = Demonstration.mod_inverse(d1, phi1, math_service)
        
        print("Generated VULNERABLE key:")
        print(f"p = {p1}, q = {q1}")
        print(f"n = p * q = {n1}")
        print(f"phi(n) = (p-1)*(q-1) = {phi1}")
        print(f"d = {d1} (small - VULNERABLE)")
        print(f"e = {e1} (calculated from d)")
        
        print("\nVerifying key correctness:")
        print(f"GCD(d, phi(n)) = {math_service.gcd(d1, phi1)} (should be 1)")
        print(f"e * d mod phi(n) = {(e1 * d1) % phi1} (should be 1)")
        
        bound1 = n1 ** 0.25
        print(f"Wiener bound (n^0.25): {bound1}")
        print(f"{d1} < {bound1}: {'YES (vulnerable)' if d1 < bound1 else 'NO (resistant)'}")
        
        message1 = 42
        encrypted1 = math_service.mod_exp(message1, e1, n1)
        decrypted1 = math_service.mod_exp(encrypted1, d1, n1)
        print(f"\nEncryption demonstration:")
        print(f"Original message: {message1}")
        print(f"Encrypted: {encrypted1}")
        print(f"Decrypted: {decrypted1}")
        print(f"Correctness: {'YES' if message1 == decrypted1 else 'NO'}")
        
        print("\nApplying Wiener attack...")
        result1 = wiener_service.attack(n1, e1)
        Demonstration.print_wiener_result(result1, d1)
        
        print("=" * 70)
        print("EXAMPLE 2: ANOTHER VULNERABLE KEY")
        print("=" * 70)
        
        p2 = 131
        q2 = 113
        n2 = p2 * q2
        phi2 = (p2 - 1) * (q2 - 1)
        
        d2 = 0
        for candidate in [3, 5, 7, 9, 11, 13, 17, 19, 21, 23, 25, 27, 29]:
            if math_service.gcd(candidate, phi2) == 1:
                d2 = candidate
                break
        
        if d2 == 0:
            raise RuntimeError(f"Could not find coprime d for phi(n)={phi2}")
        
        e2 = Demonstration.mod_inverse(d2, phi2, math_service)
        
        print("Generated VULNERABLE key:")
        print(f"p = {p2}, q = {q2}")
        print(f"n = p * q = {n2}")
        print(f"phi(n) = (p-1)*(q-1) = {phi2}")
        print(f"d = {d2} (small - VULNERABLE)")
        print(f"e = {e2} (calculated from d)")
        
        print(f"Verification: GCD(d, phi(n)) = {math_service.gcd(d2, phi2)} (should be 1)")
        print(f"Verification: e * d mod phi(n) = {(e2 * d2) % phi2} (should be 1)")
        
        bound2 = n2 ** 0.25
        print(f"Wiener bound (n^0.25): {bound2}")
        print(f"{d2} < {bound2}: {'YES (vulnerable)' if d2 < bound2 else 'NO (resistant)'}")
        
        print("\nApplying Wiener attack...")
        result2 = wiener_service.attack(n2, e2)
        Demonstration.print_wiener_result(result2, d2)
    
    @staticmethod
    def print_wiener_result(result: WienerAttackResult, expected_d: int = 0):
        print("\n" + "-" * 60)
        print("WIENER ATTACK RESULT:")
        print("-" * 60)
        
        if result.success:
            print("Attack SUCCESSFUL!")
            print(f"Found secret exponent d: {result.d}")
            
            if expected_d != 0:
                print(f"  Expected d: {expected_d}")
                print(f"  Match: {'YES' if result.d == expected_d else 'NO'}")
            
            print(f"  Computed Euler function phi(n): {result.phi}")
            print(f"  Number of convergents checked: {len(result.convergents)}")
            
            print("\n  ALL CONVERGENTS:")
            for conv in result.convergents:
                print(f"    [{conv.index:2d}]: {conv.numerator:6d} / {conv.denominator:6d}", end="")
                if conv.denominator == result.d:
                    print(" <- FOUND SECRET EXPONENT")
                else:
                    print()
        else:
            print("Attack FAILED")
            print(f"Reason: {result.error_message}")
            
            if expected_d != 0:
                print(f"  Expected d: {expected_d}")
            
            if result.convergents:
                print("\n  COMPUTED CONVERGENTS:")
                for conv in result.convergents:
                    print(f"    [{conv.index:2d}]: {conv.numerator:6d} / {conv.denominator:6d}", end="")
                    
                    if expected_d != 0 and conv.denominator == expected_d:
                        print(" <- EXPECTED d (but didn't work)")
                    else:
                        print()
        
        print("-" * 60)
        
        if result.success and expected_d != 0:
            if result.d == expected_d:
                print("Wiener attack successfully recovered the secret exponent")
            else:
                print(f"Found d = {result.d}, but expected d = {expected_d}")
        print()


def main():
    try:
        Demonstration.run()
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

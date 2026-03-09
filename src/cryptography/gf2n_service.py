from typing import List, Tuple


class ReductionPolynomialError(Exception):
    pass


class GF2NService:
    @staticmethod
    def add(a: int, b: int) -> int:
        return a ^ b
    
    @staticmethod
    def multiply(a: int, b: int, modulus: int) -> int:
        if modulus == 0:
            raise ReductionPolynomialError("Modulus cannot be zero")
        
        result = 0
        a = a & 0xFF
        
        while b:
            if b & 1:
                result ^= a
            
            a <<= 1
            if a & 0x100:
                a ^= modulus
            a &= 0xFF
            
            b >>= 1
        
        return result
    
    @staticmethod
    def xtime(a: int, modulus: int) -> int:
        a <<= 1
        if a & 0x100:
            a ^= modulus
        return a & 0xFF
    
    @staticmethod
    def inverse(a: int, modulus: int) -> int:
        if a == 0:
            return 0
        
        if modulus == 0:
            raise ReductionPolynomialError("Modulus cannot be zero")
        
        result = GF2NService._extended_gcd(a, modulus)
        
        if result[0] != 1:
            raise ReductionPolynomialError(
                f"Element {a} has no inverse with modulus {modulus}. "
                "Modulus may not be irreducible."
            )
        
        return result[1] & 0xFF
    
    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return (b, 0, 1)
        
        a = a & 0xFF
        
        new_gcd, new_x, new_y = GF2NService._extended_gcd(GF2NService._gf2_mod(b, a), a)
        
        x = new_y ^ GF2NService._gf2_multiply(new_x, GF2NService._gf2_div(b, a))
        y = new_x
        
        return (new_gcd, x, y)
    
    @staticmethod
    def _gf2_mod(a: int, b: int) -> int:
        if b == 0:
            return a
        
        deg_b = GF2NService._polynomial_degree(b)
        deg_a = GF2NService._polynomial_degree(a)
        
        while deg_a >= deg_b:
            a ^= b << (deg_a - deg_b)
            deg_a = GF2NService._polynomial_degree(a)
        
        return a
    
    @staticmethod
    def _gf2_div(a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError("Division by zero polynomial")
        
        if a == 0:
            return 0
        
        deg_b = GF2NService._polynomial_degree(b)
        deg_a = GF2NService._polynomial_degree(a)
        
        if deg_a < deg_b:
            return 0
        
        quotient = 0
        remainder = a
        
        while deg_a >= deg_b and remainder != 0:
            shift = deg_a - deg_b
            quotient ^= 1 << shift
            remainder ^= b << shift
            deg_a = GF2NService._polynomial_degree(remainder)
        
        return quotient
    
    @staticmethod
    def _gf2_multiply(a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            b >>= 1
        return result
    
    @staticmethod
    def _polynomial_degree(p: int) -> int:
        if p == 0:
            return -1
        return p.bit_length() - 1
    
    @staticmethod
    def inverse_by_exponentiation(a: int, modulus: int) -> int:
        if a == 0:
            return 0
        
        if modulus == 0:
            raise ReductionPolynomialError("Modulus cannot be zero")
        
        result = 1
        power = a
        exp = 254
        
        while exp:
            if exp & 1:
                result = GF2NService.multiply(result, power, modulus)
            power = GF2NService.multiply(power, power, modulus)
            exp >>= 1
        
        return result
    
    @staticmethod
    def is_irreducible(polynomial: int) -> bool:
        if polynomial == 0:
            return False
        
        degree = GF2NService._polynomial_degree(polynomial)
        
        if degree != 8:
            return False
        
        if polynomial & 1 == 0:
            return False
        
        x_to_2n = GF2NService._power_mod(2, 1 << degree, polynomial)
        x_to_2n_minus_x = GF2NService._gf2_mod(x_to_2n ^ 2, polynomial)
        
        if x_to_2n_minus_x != 0:
            return False
        
        return GF2NService._rabin_test(polynomial, degree)
    
    @staticmethod
    def _power_mod(base: int, exp: int, modulus: int) -> int:
        result = 1
        base = GF2NService._gf2_mod(base, modulus)
        
        while exp:
            if exp & 1:
                result = GF2NService._gf2_mod(GF2NService._gf2_multiply(result, base), modulus)
            base = GF2NService._gf2_mod(GF2NService._gf2_multiply(base, base), modulus)
            exp >>= 1
        
        return result
    
    @staticmethod
    def _gf2_multiply(a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            b >>= 1
        return result
    
    @staticmethod
    def _rabin_test(polynomial: int, degree: int) -> bool:
        divisors = GF2NService._get_proper_divisors(degree)
        
        for d in divisors:
            x_to_2d = GF2NService._power_mod(2, 1 << d, polynomial)
            g = GF2NService._gf2_gcd(
                polynomial,
                GF2NService._gf2_mod(x_to_2d ^ 2, polynomial)
            )
            if g != 1:
                return False
        
        return True
    
    @staticmethod
    def _gf2_gcd(a: int, b: int) -> int:
        while b:
            a, b = b, GF2NService._gf2_mod(a, b)
        return a
    
    @staticmethod
    def _get_proper_divisors(n: int) -> List[int]:
        if n <= 1:
            return []
        
        divisors = []
        for d in range(1, n):
            if n % d == 0:
                divisors.append(d)
        
        return divisors
    
    @staticmethod
    def get_all_irreducible() -> List[int]:
        irreducibles = []
        
        for p in range(0x100, 0x200):
            if p & 1:
                if GF2NService.is_irreducible(p):
                    irreducibles.append(p)
        
        return irreducibles
    
    @staticmethod
    def factor_polynomial(polynomial: int) -> List[int]:
        if polynomial == 0:
            return []
        
        if polynomial == 1:
            return []
        
        degree = GF2NService._polynomial_degree(polynomial)
        
        if degree <= 0:
            return []
        
        if GF2NService._is_irreducible_general(polynomial):
            return [polynomial]
        
        factor = GF2NService._find_factor(polynomial)
        if factor is None:
            return [polynomial]
        
        quotient = GF2NService._gf2_div(polynomial, factor)
        
        left_factors = GF2NService.factor_polynomial(factor)
        right_factors = GF2NService.factor_polynomial(quotient)
        
        return left_factors + right_factors
    
    @staticmethod
    def _is_irreducible_general(polynomial: int) -> bool:
        if polynomial == 0:
            return False
        
        degree = GF2NService._polynomial_degree(polynomial)
        
        if degree <= 0:
            return False
        
        if polynomial & 1 == 0:
            return False
        
        x_to_2n = 1 << (2 * degree)
        remainder = GF2NService._gf2_mod(x_to_2n ^ (1 << degree), polynomial)
        
        if remainder != 0:
            return False
        
        divisors = GF2NService._get_proper_divisors(degree)
        for d in divisors:
            x_to_2d = 1 << (2 * d)
            g = GF2NService._gf2_gcd(
                polynomial,
                GF2NService._gf2_mod(x_to_2d ^ (1 << d), polynomial)
            )
            if g != 1:
                return False
        
        return True
    
    @staticmethod
    def _find_factor(polynomial: int) -> int:
        degree = GF2NService._polynomial_degree(polynomial)
        
        for d in range(1, degree // 2 + 1):
            g = GF2NService._compute_gcd_with_x2d_x(polynomial, d)
            if g != 1 and g != polynomial:
                return g
        
        return None
    
    @staticmethod
    def _compute_gcd_with_x2d_x(polynomial: int, d: int) -> int:
        x_2d = 1 << (2 * d)
        x_d = 1 << d
        
        diff = x_2d ^ x_d
        
        remainder = GF2NService._gf2_mod(diff, polynomial)
        
        return GF2NService._gf2_gcd(polynomial, remainder)


AES_MODULUS = 0x11B

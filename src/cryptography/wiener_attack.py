from dataclasses import dataclass, field
from typing import List, Optional
from src.cryptography.math_service import IMathService, MathService


@dataclass
class ConvergentFraction:
    numerator: int
    denominator: int
    index: int
    
    def __init__(self, numerator: int, denominator: int, index: int):
        self.numerator = numerator
        self.denominator = denominator
        self.index = index


@dataclass
class WienerAttackResult:
    success: bool
    d: int
    phi: int
    convergents: List[ConvergentFraction]
    error_message: str
    
    def __init__(self):
        self.success = False
        self.d = 0
        self.phi = 0
        self.convergents = []
        self.error_message = ""


class IWienerAttackService:
    def attack(self, n: int, e: int) -> WienerAttackResult:
        raise NotImplementedError


class WienerAttackService(IWienerAttackService):
    def __init__(self, math_service: Optional[IMathService] = None):
        self._math_service = math_service if math_service else MathService()
    
    def attack(self, n: int, e: int) -> WienerAttackResult:
        result = WienerAttackResult()
        
        print("WIENER ATTACK STARTED")
        print(f"n = {n}")
        print(f"e = {e}")
        
        if n <= 0 or e <= 0:
            result.success = False
            result.error_message = "Invalid n or e values"
            return result
        
        print("1. COMPUTING CONTINUED FRACTION FOR e/n")
        continued_fraction = self._compute_continued_fraction(e, n)
        
        print(f"Continued fraction: {continued_fraction}")
        
        print("2. COMPUTING CONVERGENTS")
        result.convergents = self._compute_convergents(continued_fraction)
        
        print(f"Found {len(result.convergents)} convergents:")
        for conv in result.convergents:
            approx = conv.numerator / conv.denominator if conv.denominator != 0 else 0
            print(f"  [{conv.index}]: {conv.numerator}/{conv.denominator} ≈ {approx:.6f}")
        
        print("3. SEARCHING FOR SECRET EXPONENT d")
        
        wiener_bound = int(n ** 0.25)
        print(f"Wiener bound: d < {wiener_bound}")
        
        for conv in result.convergents:
            k = conv.numerator
            d_candidate = conv.denominator
            
            if d_candidate == 0 or k == 0:
                continue
            
            if d_candidate > wiener_bound:
                print(f"Skipping fraction {k}/{d_candidate} (d > {wiener_bound})")
                continue
            
            print(f"Checking fraction {k}/{d_candidate}: ", end="")
            
            phi_candidate = 0
            valid, phi_candidate = self._is_valid_candidate(n, e, k, d_candidate)
            if valid:
                print("SUCCESS!")
                print(f"  Found secret exponent d = {d_candidate}")
                print(f"  phi(n) = {phi_candidate}")
                
                result.success = True
                result.d = d_candidate
                result.phi = phi_candidate
                
                print("ATTACK SUCCESSFULLY COMPLETED")
                return result
            else:
                print("not suitable")
        
        result.success = False
        result.error_message = "Secret exponent not found - key is resistant to Wiener attack"
        print("ATTACK FAILED")
        print(result.error_message)
        
        return result
    
    def _compute_continued_fraction(self, a: int, b: int) -> List[int]:
        coefficients = []
        
        while b != 0:
            quotient = a // b
            coefficients.append(quotient)
            a, b = b, a % b
        
        return coefficients
    
    def _compute_convergents(self, coefficients: List[int]) -> List[ConvergentFraction]:
        convergents = []
        
        if not coefficients:
            return convergents
        
        h0, h1 = 0, 1
        k0, k1 = 1, 0
        
        for i, a in enumerate(coefficients):
            h2 = a * h1 + h0
            k2 = a * k1 + k0
            
            convergents.append(ConvergentFraction(h2, k2, i))
            
            h0, h1 = h1, h2
            k0, k1 = k1, k2
        
        return convergents
    
    def _is_valid_candidate(self, n: int, e: int, k: int, d: int) -> tuple:
        if d == 0 or k == 0:
            return False, 0
        
        if (e * d) % k != 1:
            return False, 0
        
        ed_minus_one = e * d - 1
        if ed_minus_one % k != 0:
            return False, 0
        
        phi_candidate = ed_minus_one // k
        
        if phi_candidate <= 0 or phi_candidate >= n:
            return False, 0
        
        p, q = self._factorize_n(n, phi_candidate)
        if p > 0 and q > 0:
            print()
            print(f"  Found factors: p = {p}, q = {q}")
            print(f"  Verification: p*q = {p*q}, n = {n}")
            print(f"  Verification: (p-1)*(q-1) = {(p-1)*(q-1)}, phi = {phi_candidate}")
            return True, phi_candidate
        
        return False, 0
    
    def _factorize_n(self, n: int, phi: int) -> tuple:
        b = n - phi + 1
        discriminant = b * b - 4 * n
        
        if discriminant < 0:
            return 0, 0
        
        sqrt_disc = int(discriminant ** 0.5)
        
        if sqrt_disc * sqrt_disc != discriminant:
            return 0, 0
        
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        
        if p > 0 and q > 0 and p * q == n:
            return p, q
        
        return q, p

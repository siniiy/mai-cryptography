from abc import ABC, abstractmethod
from typing import Tuple


class IMathService(ABC):
    @abstractmethod
    def legendre_symbol(self, a: int, p: int) -> int:
        pass
    
    @abstractmethod
    def jacobi_symbol(self, a: int, n: int) -> int:
        pass
    
    @abstractmethod
    def gcd(self, a: int, b: int) -> int:
        pass
    
    @abstractmethod
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        pass
    
    @abstractmethod
    def mod_exp(self, base: int, exponent: int, modulus: int) -> int:
        pass


class MathService(IMathService):
    def legendre_symbol(self, a: int, p: int) -> int:
        if p <= 0 or p % 2 == 0:
            raise ValueError("p must be an odd prime")
        
        a = a % p
        if a == 0:
            return 0
        
        result = self.mod_exp(a, (p - 1) // 2, p)
        return 1 if result == 1 else -1
    
    def jacobi_symbol(self, a: int, n: int) -> int:
        if n <= 0 or n % 2 == 0:
            raise ValueError("n must be an odd positive integer")
        
        a = a % n
        if a == 0:
            return 0
        
        result = 1
        
        while a != 0:
            while a % 2 == 0:
                a //= 2
                mod8 = n % 8
                if mod8 == 3 or mod8 == 5:
                    result = -result
            
            if a % 4 == 3 and n % 4 == 3:
                result = -result
            
            a, n = n, a
            a = a % n
        
        return result if n == 1 else 0
    
    def gcd(self, a: int, b: int) -> int:
        a = abs(a)
        b = abs(b)
        
        while b != 0:
            temp = b
            b = a % b
            a = temp
        
        return a
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return (b, 0, 1)
        
        gcd_val, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return (gcd_val, x, y)
    
    def mod_exp(self, base: int, exponent: int, modulus: int) -> int:
        if modulus == 1:
            return 0
        
        result = 1
        base = base % modulus
        
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus
        
        return result

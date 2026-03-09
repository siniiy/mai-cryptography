from abc import ABC, abstractmethod
import random
from typing import Optional
from src.cryptography.math_service import IMathService, MathService


class IPrimalityTest(ABC):
    @abstractmethod
    def is_probably_prime(self, n: int, min_probability: float = 0.99) -> bool:
        pass


class BasePrimalityTest(IPrimalityTest):
    def __init__(self, math_service: Optional[IMathService] = None):
        self._math_service = math_service if math_service else MathService()
        self._rng = random.Random()
    
    def is_probably_prime(self, n: int, min_probability: float = 0.99) -> bool:
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        required_iterations = self._calculate_required_iterations(min_probability)
        
        for _ in range(required_iterations):
            if not self._single_iteration_test(n):
                return False
        
        return True
    
    def _calculate_required_iterations(self, min_probability: float) -> int:
        if min_probability < 0.5 or min_probability >= 1.0:
            raise ValueError("Probability must be in range [0.5, 1)")
        
        error_per_iteration = 0.25
        k = 0
        current_prob = 0.0
        
        while current_prob < min_probability:
            k += 1
            current_prob = 1.0 - (error_per_iteration ** k)
        
        return k
    
    def _get_random_witness(self, n: int) -> int:
        return self._rng.randint(2, n - 2)
    
    @abstractmethod
    def _single_iteration_test(self, n: int) -> bool:
        pass


class FermatTest(BasePrimalityTest):
    def _single_iteration_test(self, n: int) -> bool:
        a = self._get_random_witness(n)
        return self._math_service.mod_exp(a, n - 1, n) == 1


class SolovayStrassenTest(BasePrimalityTest):
    def _single_iteration_test(self, n: int) -> bool:
        a = self._get_random_witness(n)
        
        jacobi = self._math_service.jacobi_symbol(a, n)
        if jacobi == 0:
            return False
        
        mod_exp_result = self._math_service.mod_exp(a, (n - 1) // 2, n)
        jacobi_mod = (jacobi % n + n) % n
        
        return mod_exp_result == jacobi_mod


class MillerRabinTest(BasePrimalityTest):
    def _single_iteration_test(self, n: int) -> bool:
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        
        a = self._get_random_witness(n)
        x = self._math_service.mod_exp(a, d, n)
        
        if x == 1 or x == n - 1:
            return True
        
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return True
            if x == 1:
                return False
        
        return False

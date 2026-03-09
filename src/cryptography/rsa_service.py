from dataclasses import dataclass
from typing import Tuple, Optional
import random
from src.cryptography.math_service import IMathService, MathService
from src.cryptography.primality_tests import BasePrimalityTest, FermatTest, SolovayStrassenTest, MillerRabinTest


@dataclass
class RSAKeyPair:
    public_key: Tuple[int, int]
    private_key: Tuple[int, int]
    
    def __init__(self, n: int, e: int, d: int):
        self.public_key = (n, e)
        self.private_key = (n, d)


class IRSAGenerator:
    def generate_key_pair(self, bit_length: int) -> RSAKeyPair:
        raise NotImplementedError


class IRSAService:
    def encrypt(self, message: int, public_key: Tuple[int, int]) -> int:
        raise NotImplementedError
    
    def decrypt(self, ciphertext: int, private_key: Tuple[int, int]) -> int:
        raise NotImplementedError
    
    def generate_new_key_pair(self) -> None:
        raise NotImplementedError
    
    def get_current_key_pair(self) -> RSAKeyPair:
        raise NotImplementedError


class RSAService(IRSAService):
    class PrimalityTestType:
        FERMAT = 0
        SOLOVAY_STRASSEN = 1
        MILLER_RABIN = 2
    
    class RSAGenerator(IRSAGenerator):
        def __init__(self, test_type: int, probability: float, math_service: IMathService):
            self._test_type = test_type
            self._min_probability = probability
            self._math_service = math_service
            self._rng = random.Random()
            self._primality_test: Optional[BasePrimalityTest] = None
            self._setup_primality_test()
        
        def _setup_primality_test(self) -> None:
            if self._test_type == RSAService.PrimalityTestType.FERMAT:
                self._primality_test = FermatTest(self._math_service)
            elif self._test_type == RSAService.PrimalityTestType.SOLOVAY_STRASSEN:
                self._primality_test = SolovayStrassenTest(self._math_service)
            elif self._test_type == RSAService.PrimalityTestType.MILLER_RABIN:
                self._primality_test = MillerRabinTest(self._math_service)
            else:
                raise ValueError("Unknown test type")
        
        def _is_small_prime(self, n: int) -> bool:
            if n < 2:
                return False
            if n == 2:
                return True
            if n % 2 == 0:
                return False
            for i in range(3, int(n ** 0.5) + 1, 2):
                if n % i == 0:
                    return False
            return True
        
        def _generate_large_prime(self, bit_length: int) -> int:
            print(f"    Searching for {bit_length}-bit prime...")
            
            min_val = 2 ** (bit_length - 1)
            max_val = 2 ** bit_length - 1
            
            attempts = 0
            max_attempts = 1000
            
            while attempts < max_attempts:
                attempts += 1
                candidate = self._rng.randint(min_val, max_val)
                if candidate % 2 == 0:
                    candidate += 1
                
                if self._is_small_prime(candidate % 1000):
                    if self._primality_test.is_probably_prime(candidate, self._min_probability):
                        print(f"    Found prime: {candidate}")
                        return candidate
            
            raise RuntimeError(f"Failed to generate prime after {max_attempts} attempts")
        
        def _is_secure_prime_pair(self, p: int, q: int, n: int) -> bool:
            if p == q:
                return False
            
            diff = abs(p - q)
            min_diff = 2 ** (len(bin(n)) - 2 - 100)
            if diff < min_diff:
                return False
            
            return True
        
        def generate_key_pair(self, bit_length: int) -> RSAKeyPair:
            print(f"  Starting RSA key generation ({bit_length} bits)...")
            
            attempts = 0
            max_attempts = 500
            
            while attempts < max_attempts:
                attempts += 1
                print(f"  Attempt {attempts}/{max_attempts}")
                
                try:
                    p = self._generate_large_prime(bit_length // 2)
                    q = self._generate_large_prime(bit_length // 2)
                    
                    print(f"    p = {p}")
                    print(f"    q = {q}")
                    
                    if not self._is_secure_prime_pair(p, q, 2 ** bit_length):
                        print("    Insecure prime pair, trying again...")
                        continue
                    
                    n = p * q
                    phi = (p - 1) * (q - 1)
                    
                    print(f"    n = {n}")
                    print(f"    phi = {phi}")
                    
                    possible_e = [3, 5, 17, 257, 65537]
                    e = 0
                    d = 0
                    
                    for candidate_e in possible_e:
                        if candidate_e < phi and self._math_service.gcd(candidate_e, phi) == 1:
                            e = candidate_e
                            print(f"    Selected e = {e}")
                            
                            gcd_val, x, _ = self._math_service.extended_gcd(e, phi)
                            d = x % phi
                            if d < 0:
                                d += phi
                            
                            print(f"    Computed d = {d}")
                            break
                    
                    if e == 0:
                        print("    No suitable e found, trying again...")
                        continue
                    
                    wiener_bound = int(n ** 0.25)
                    if d < wiener_bound:
                        print(f"    d too small (vulnerable to Wiener attack), trying again...")
                        continue
                    
                    print("    Testing keys...")
                    test_msg = 42
                    encrypted = self._math_service.mod_exp(test_msg, e, n)
                    decrypted = self._math_service.mod_exp(encrypted, d, n)
                    
                    if test_msg == decrypted:
                        print("    Keys successfully generated and verified!")
                        return RSAKeyPair(n, e, d)
                    else:
                        print("    Key verification failed, trying again...")
                
                except Exception as ex:
                    print(f"    Error: {ex}, trying again...")
                    continue
            
            raise RuntimeError(f"Failed to generate keys after {max_attempts} attempts")
    
    def __init__(self, test_type: int, min_probability: float, bit_length: int = 1024):
        self._math_service = MathService()
        self._generator = self.RSAGenerator(test_type, min_probability, self._math_service)
        self._bit_length = bit_length
        self._current_key_pair: Optional[RSAKeyPair] = None
        
        if min_probability < 0.5 or min_probability >= 1.0:
            raise ValueError("Probability must be in range [0.5, 1)")
        
        if bit_length < 16:
            raise ValueError("Key length must be at least 16 bits")
        
        self.generate_new_key_pair()
    
    def encrypt(self, message: int, public_key: Tuple[int, int]) -> int:
        n, e = public_key
        
        if n <= 0 or e <= 0:
            raise ValueError("Invalid public key")
        
        if message < 0:
            raise ValueError("Message cannot be negative")
        
        if message >= n:
            raise ValueError("Message too large for key")
        
        return self._math_service.mod_exp(message, e, n)
    
    def decrypt(self, ciphertext: int, private_key: Tuple[int, int]) -> int:
        n, d = private_key
        
        if n <= 0 or d <= 0:
            raise ValueError("Invalid private key")
        
        if ciphertext < 0:
            raise ValueError("Ciphertext cannot be negative")
        
        if ciphertext >= n:
            raise ValueError("Ciphertext too large for key")
        
        return self._math_service.mod_exp(ciphertext, d, n)
    
    def generate_new_key_pair(self) -> None:
        print("Generating new RSA key pair...")
        self._current_key_pair = self._generator.generate_key_pair(self._bit_length)
        print("Key generation completed successfully!")
    
    def get_current_key_pair(self) -> RSAKeyPair:
        if self._current_key_pair is None or self._current_key_pair.public_key[0] == 0:
            raise RuntimeError("Keys not yet generated")
        return self._current_key_pair

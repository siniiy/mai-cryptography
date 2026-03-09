from typing import List

from .feistel_net import FeistelNet
from .interfaces import (
        IRoundKeyGen,
        IRoundKeyEncryption,
        ISymmetricBlockEncryption
    )
from .des_implementation import Des


DEAL_CONSTANTS = [
    0x0000000000000000,
    0x0000000000000001,
    0x0000000000000002,
    0x0000000000000004,
    0x0000000000000008,
    0x0000000000000010,
    0x0000000000000020,
    0x0000000000000040,
]


class DealRoundKeyEncryption(IRoundKeyEncryption):
    """
    Adapter class that allows using DES as the round function in DEAL.
    Implements IRoundKeyEncryption interface.
    """
    
    @staticmethod
    def encrypt(value: bytes, round_key: bytes) -> bytes:
        """
        Encrypt a 64-bit value using DES with the given round key.
        
        Args:
            value: 64-bit (8-byte) block to encrypt
            round_key: 64-bit (8-byte) DES key
            
        Returns:
            64-bit encrypted block
        """
        des = Des()
        des.key = round_key
        result = bytearray(8)
        des.encrypt(value, result)
        return bytes(result)


class DealRoundKeysGen(IRoundKeyGen):
    """
    Generates round keys for DEAL algorithm.
    Implements IRoundKeyGen interface.
    """
    
    @staticmethod
    def expand_key(input_key: bytes) -> List[bytes]:
        """
        Generate round keys from the input key.
        
        DEAL key schedule:
        1. Split key into 64-bit blocks K1, K2, K3, K4
        2. Generate intermediate keys using DES:
           RK[0] = DES(0x0101010101010101, K1)
           RK[i] = DES(RK[i-1], K[(i mod n) + 1])
        3. XOR with constants for additional round keys
        
        Args:
            input_key: 128, 192, or 256-bit key (16, 24, or 32 bytes)
            
        Returns:
            List of 64-bit round keys
        """
        key_len = len(input_key)
        
        if key_len == 16:
            n_key_blocks = 2
            n_rounds = 6
        elif key_len == 24:
            n_key_blocks = 3
            n_rounds = 6
        elif key_len == 32:
            n_key_blocks = 4
            n_rounds = 8
        else:
            raise ValueError(f"DEAL key must be 16, 24, or 32 bytes, got {key_len}")
        
        key_blocks = []
        for i in range(n_key_blocks):
            key_blocks.append(input_key[i * 8:(i + 1) * 8])
        
        des = Des()
        
        intermediate_keys = []
        
        constant_block = bytes([0x01] * 8)
        
        for i in range(n_rounds):
            key_block = key_blocks[i % n_key_blocks]
            
            des.key = key_block
            
            if i == 0:
                input_block = constant_block
            else:
                input_block = intermediate_keys[i - 1]
            
            result = bytearray(8)
            des.encrypt(input_block, result)
            intermediate_keys.append(bytes(result))
        
        round_keys = []
        for i in range(n_rounds):
            const_bytes = DEAL_CONSTANTS[i].to_bytes(8, 'big')
            round_key = bytes(a ^ b for a, b in zip(intermediate_keys[i], const_bytes))
            round_keys.append(round_key)
        
        return round_keys


class Deal(ISymmetricBlockEncryption):
    """
    Implementation of DEAL (Data Encryption Algorithm with Larger blocks).
    
    DEAL is a Feistel cipher that uses DES as its round function.
    - Block size: 128 bits (16 bytes)
    - Key sizes: 128, 192, or 256 bits
    - Rounds: 6 for 128/192-bit keys, 8 for 256-bit keys
    """
    
    BLOCK_SIZE = 16
    
    def __init__(self) -> None:
        self._feistel_net = FeistelNet(
            DealRoundKeysGen(),
            DealRoundKeyEncryption()
        )
        self._feistel_net.block_size = self.BLOCK_SIZE
        self._key = None
        self._n_rounds = None
    
    def _get_round_count(self, key_len: int) -> int:
        """Get the number of rounds based on key length."""
        if key_len == 16:
            return 6
        elif key_len == 24:
            return 6
        elif key_len == 32:
            return 8
        else:
            raise ValueError(f"Invalid key length: {key_len}")
    
    def encrypt(self, value: bytes, result: bytearray) -> bytes:
        """
        Encrypt a 128-bit block using DEAL.
        
        Args:
            value: 128-bit (16-byte) plaintext block
            result: bytearray to store the result
            
        Returns:
            128-bit ciphertext block
        """
        if len(value) != self.BLOCK_SIZE:
            raise ValueError(f"DEAL operates on {self.BLOCK_SIZE}-byte blocks, got {len(value)}")
        
        half_len = self.BLOCK_SIZE // 2
        L, R = value[:half_len], value[half_len:]
        
        round_keys = self._feistel_net._round_keys
        
        for i in range(self._n_rounds):
            f_result = DealRoundKeyEncryption.encrypt(R, round_keys[i])
            new_R = bytes(a ^ b for a, b in zip(L, f_result))
            L = R
            R = new_R
        
        final = R + L
        
        result[:] = final
        return final
    
    def decrypt(self, value: bytes, result: bytearray) -> bytes:
        """
        Decrypt a 128-bit block using DEAL.
        
        Args:
            value: 128-bit (16-byte) ciphertext block
            result: bytearray to store the result
            
        Returns:
            128-bit plaintext block
        """
        if len(value) != self.BLOCK_SIZE:
            raise ValueError(f"DEAL operates on {self.BLOCK_SIZE}-byte blocks, got {len(value)}")
        
        half_len = self.BLOCK_SIZE // 2
        L, R = value[:half_len], value[half_len:]
        
        round_keys = self._feistel_net._round_keys[::-1]
        
        for i in range(self._n_rounds):
            f_result = DealRoundKeyEncryption.encrypt(R, round_keys[i])
            new_R = bytes(a ^ b for a, b in zip(L, f_result))
            L = R
            R = new_R
        
        final = R + L
        
        result[:] = final
        return final
    
    @property
    def key(self):
        return self._key
    
    @key.setter
    def key(self, value: bytes):
        key_len = len(value)
        if key_len not in (16, 24, 32):
            raise ValueError(f"DEAL key must be 16, 24, or 32 bytes, got {key_len}")
        
        self._key = value
        self._n_rounds = self._get_round_count(key_len)
        self._feistel_net._n_rounds = self._n_rounds
        self._feistel_net._round_keys = DealRoundKeysGen.expand_key(value)


if __name__ == '__main__':
    pass

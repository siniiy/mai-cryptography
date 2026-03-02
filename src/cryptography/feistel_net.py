from typing import List
from .interfaces import (
        IRoundKeyGen,
        IRoundKeyEncryption,
        ISymmetricBlockEncryption
    )

class FeistelNet:
    def __init__(self, round_keygen: IRoundKeyGen, encrypter: IRoundKeyEncryption):
        self._key = None
        self._round_keys = None
        self._round_keys_gen = round_keygen
        self._feistel_func = encrypter.encrypt
        self._n_rounds = None
        self._block_size = None
    
    def encrypt(self, value: bytes) -> bytes:
        if (self._round_keys is None or self._n_rounds is None or self._block_size is None):
            raise RuntimeError("Key, n_rounds and block size must be set before encrypting")
            
        return self._encrypt_block(value, decrypt=False)
            
    def _encrypt_block(self, value: bytes, decrypt: bool = False):
        if decrypt: round_keys = self._round_keys[::-1]
        else: round_keys = self._round_keys
        
        half_len = len(value) // 2
        L, R = value[:half_len], value[half_len:]
        
        for i in range(self._n_rounds):
            f_result = self._feistel_func(R, round_keys[i])
            new_R = bytes(a ^ b for a, b in zip(L, f_result))
            L = R
            R = new_R
        
        # Final swap: output is R16L16
        return R + L
    
    def decrypt(self, value: bytes) -> bytes:
        if (self._round_keys is None or self._n_rounds is None or self._block_size is None):
            raise RuntimeError("Key, n_rounds and block size must be set defore decrypting")
            
        return self._encrypt_block(value, decrypt=True)        
    
    @property
    def key(self):
        return "sosal"

    @key.setter
    def key(self, value: bytes):
        self._round_keys = self._round_keys_gen.expand_key(value)
        
    @property
    def n_rounds(self):
        return self._n_rounds
    
    @n_rounds.setter
    def n_rounds(self, value: int):
        self._n_rounds = value
        
    @property
    def block_size(self):
        return self._block_size
    
    @block_size.setter
    def block_size(self, value: int):
        self._block_size = value
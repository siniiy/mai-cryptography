from typing import List
from interfaces import (
        IRoundKeyGen,
        IRoundKeyEncryption,
        ISymmetricBlockEncryption
    )

class FeistelNet:
    def init(self, round_keygen: IRoundKeyGen, encrypter: IRoundKeyEncryption):
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
        L, R = value[:len(value) / 2], value[-(len(value) / 2):]
        for i in range(self._n_rounds):
            tmp_L = L.copy()
            L = R ^ self._feistel_func(L, round_keys[i])
            R = tmp_L
        
        R, L = L, R
        
        return bytes(L + R)
    
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
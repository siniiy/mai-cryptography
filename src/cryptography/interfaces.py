from abc import ABC, abstractmethod
from typing import List
from pathlib import Path

# 2.1
class IRoundKeyGen(ABC):
    @staticmethod
    @abstractmethod
    def expand_key(input_key: bytes) -> List[bytes]:
        pass

#2.2
class IRoundKeyEncryption(ABC):
    @staticmethod
    @abstractmethod
    def encrypt(value: bytes, round_key: bytes) -> bytes:
        pass
    
#2.3
class ISymmetricBlockEncryption(ABC):
    @abstractmethod
    def encrypt(self, value: bytes, result: bytearray) -> bytes:
        pass
    
    @abstractmethod
    def decrypt(self, value: bytes, result: bytearray) -> bytes:
        pass
    
    @property
    @abstractmethod
    def key(self):
        pass
    
    @key.setter
    @abstractmethod
    def key(self, key: bytes):
        pass
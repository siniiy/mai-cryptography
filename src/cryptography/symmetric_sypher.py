from pathlib import Path

from .interfaces import (
    IRoundKeyGen,
    IRoundKeyEncryption,
    ISymmetricBlockEncryption
)

from .paddings import (
    Padding_Mode,
    PaddingAction
)

from .modes import (
    Cipher_Mode,
    SymmetricBlockCipherAction
)

BLOCK_SIZE = 64

class SymmetricEncryption:
    def __init__(
        self,
        key: bytes,
        cipher_mode: Cipher_Mode,
        padding_mode: Padding_Mode,
        init_vector: bytes = None,
        *args
        ) -> None:
        if not (isinstance(cipher_mode, Cipher_Mode) or isinstance(padding_mode, Padding_Mode)):
            raise TypeError("Cipher mode and Padding modes have to be enums")
            
        self._mode = cipher_mode
        self._padding_mode = padding_mode
        self._key = key
        self._iv = init_vector
        
        self._padding_actor = PaddingAction(self._padding_mode, BLOCK_SIZE)
        
        self._de_encryption_actor = SymmetricBlockCipherAction(cipher_mode, init_vector, BLOCK_SIZE, *args)
        self._de_encryption_actor.set_key(key)
        
    def _is_padding_needed(self, value: bytes) -> bool:
        #Блочные режимы
        if self._mode not in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            return False

        if not (len(value) % BLOCK_SIZE):
            return True

        # Фулл блок
        if self._padding_mode in {
            Padding_Mode.PKCS7, 
            Padding_Mode.ANSI_X_923, 
            Padding_Mode.ISO_10126
        }:
            return True

        # Zeros
        return False

    def encrypt_bytes(self, value: bytes, result: bytearray) -> bytes:
        if self._is_padding_needed(value):
            value = self._padding_actor.pad(value)
        
        self._de_encryption_actor.encrypt(value, result)
        return bytes(result)

    def decrypt_bytes(self, value: bytes, result: bytearray) -> bytes:
        if self._mode in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            if len(value) % BLOCK_SIZE != 0:
                raise ValueError()

        self._de_encryption_actor.decrypt(value, result)

        if self._mode in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            plain = self._padding_actor.unpad(bytes(result))
            result[:] = plain 

        return bytes(result)

    def encrypt_file(self, input_filepath: Path, output_filepath: Path):
        if not input_filepath.exists() or not input_filepath.is_file():
            raise FileNotFoundError(f"Input file not found: {input_filepath}")

        data = input_filepath.read_bytes()
        buf = bytearray()
        enc = self.encrypt_bytes(data, buf)
        output_filepath.write_bytes(enc)

    def decrypt_file(self, input_filepath: Path, output_filepath: Path):
        if not input_filepath.exists() or not input_filepath.is_file():
            raise FileNotFoundError(f"Input file not found: {input_filepath}")

        data = input_filepath.read_bytes()

        if self._mode in {
            Cipher_Mode.ECB,
            Cipher_Mode.CBC,
            Cipher_Mode.PCBC
        }:
            if len(data) % BLOCK_SIZE != 0:
                raise ValueError()

        buf = bytearray()
        dec = self.decrypt_bytes(data, buf)
        output_filepath.write_bytes(dec)
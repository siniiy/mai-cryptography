#!/usr/bin/env python3
"""
Rijndael Demo Script
Tests the Rijndael implementation with known test vectors from FIPS 197 (AES) 
and additional tests for variable block/key sizes
"""

import sys
import os
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptography.rijndael_implementation import Rijndael
from cryptography.demonstrator import FileCipher
from cryptography.modes import Cipher_Mode
from cryptography.paddings import Padding_Mode


def test_aes_vectors():
    """Test AES (128-bit block) with known test vectors from FIPS 197"""
    
    test_cases = [
        {
            'name': 'AES-128, Appendix B.1',
            'key': bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C'),
            'plaintext': bytes.fromhex('3243F6A8885A308D313198A2E0370734'),
            'ciphertext': bytes.fromhex('3925841D02DC09FBDC118597196A0B32')
        },
        {
            'name': 'AES-128, zero plaintext',
            'key': bytes.fromhex('00000000000000000000000000000000'),
            'plaintext': bytes.fromhex('00000000000000000000000000000000'),
            'ciphertext': bytes.fromhex('66E94BD4EF8A2C3B884CFA59CA342B2E')
        },
        {
            'name': 'AES-192, zero plaintext',
            'key': bytes.fromhex('000000000000000000000000000000000000000000000000'),
            'plaintext': bytes.fromhex('00000000000000000000000000000000'),
            'ciphertext': bytes.fromhex('AAE0695AC6D8A50A4E5BEB8F4257B4B1')
        },
        {
            'name': 'AES-256, zero plaintext',
            'key': bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000'),
            'plaintext': bytes.fromhex('00000000000000000000000000000000'),
            'ciphertext': bytes.fromhex('DC95C078A2408989AD48A21492842087')
        },
        {
            'name': 'AES-128, all ones key',
            'key': bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
            'plaintext': bytes.fromhex('00000000000000000000000000000000'),
            'ciphertext': bytes.fromhex('A1F6258C877D5FCD8964484538BFC92C')
        },
    ]
    
    print("AES Test Vectors (FIPS 197)")
    print("=" * 60)
    
    all_passed = True
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTest Case {i}: {test['name']}")
        print(f"Key:        {test['key'].hex().upper()}")
        print(f"Plaintext:  {test['plaintext'].hex().upper()}")
        print(f"Expected:   {test['ciphertext'].hex().upper()}")
        
        try:
            rijndael = Rijndael(block_size=16)
            rijndael.key = test['key']
            
            encrypted_result = bytearray(16)
            rijndael.encrypt(test['plaintext'], encrypted_result)
            encrypted = bytes(encrypted_result)
            
            print(f"Encrypted:  {encrypted.hex().upper()}")
            
            decrypted_result = bytearray(16)
            rijndael.decrypt(encrypted, decrypted_result)
            decrypted = bytes(decrypted_result)
            
            print(f"Decrypted:  {decrypted.hex().upper()}")
            
            encrypt_ok = encrypted == test['ciphertext']
            decrypt_ok = decrypted == test['plaintext']
            
            if encrypt_ok and decrypt_ok:
                print("✓ PASS")
            else:
                print("✗ FAIL")
                if not encrypt_ok:
                    print(f"  Encryption failed: expected {test['ciphertext'].hex()}, got {encrypted.hex()}")
                if not decrypt_ok:
                    print(f"  Decryption failed: expected {test['plaintext'].hex()}, got {decrypted.hex()}")
                all_passed = False
                
        except Exception as e:
            print(f"✗ FAIL - Exception: {e}")
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("All tests PASSED! ✓")
    else:
        print("Some tests FAILED! ✗")
    
    return all_passed


def test_variable_block_sizes():
    """Test Rijndael with variable block sizes (16, 24, 32 bytes)"""
    
    print("\nVariable Block Size Test")
    print("=" * 60)
    
    test_configs = [
        {'block_size': 16, 'key_size': 16, 'name': '128-bit block, 128-bit key'},
        {'block_size': 16, 'key_size': 24, 'name': '128-bit block, 192-bit key'},
        {'block_size': 16, 'key_size': 32, 'name': '128-bit block, 256-bit key'},
        {'block_size': 24, 'key_size': 16, 'name': '192-bit block, 128-bit key'},
        {'block_size': 24, 'key_size': 24, 'name': '192-bit block, 192-bit key'},
        {'block_size': 24, 'key_size': 32, 'name': '192-bit block, 256-bit key'},
        {'block_size': 32, 'key_size': 16, 'name': '256-bit block, 128-bit key'},
        {'block_size': 32, 'key_size': 24, 'name': '256-bit block, 192-bit key'},
        {'block_size': 32, 'key_size': 32, 'name': '256-bit block, 256-bit key'},
    ]
    
    all_passed = True
    
    for config in test_configs:
        block_size = config['block_size']
        key_size = config['key_size']
        
        print(f"\nTesting: {config['name']}")
        
        try:
            rijndael = Rijndael(block_size=block_size)
            
            key = bytes([i % 256 for i in range(key_size)])
            plaintext = bytes([i % 256 for i in range(block_size)])
            
            rijndael.key = key
            
            encrypted_result = bytearray(block_size)
            rijndael.encrypt(plaintext, encrypted_result)
            encrypted = bytes(encrypted_result)
            
            decrypted_result = bytearray(block_size)
            rijndael.decrypt(encrypted, decrypted_result)
            decrypted = bytes(decrypted_result)
            
            if plaintext == decrypted:
                print(f"  ✓ PASS - Round-trip successful")
                print(f"  Encrypted: {encrypted.hex().upper()[:32]}...")
            else:
                print(f"  ✗ FAIL - Round-trip failed")
                print(f"  Original:  {plaintext.hex()}")
                print(f"  Decrypted: {decrypted.hex()}")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            all_passed = False
    
    return all_passed


def test_round_trip():
    """Test encrypt/decrypt round-trip with random data"""
    import random
    
    print("\nRound-trip Test")
    print("=" * 40)
    
    all_passed = True
    
    for block_size in [16, 24, 32]:
        print(f"\nTesting with {block_size * 8}-bit block:")
        
        for key_size in [16, 24, 32]:
            print(f"  {key_size * 8}-bit key:")
            
            for i in range(2):
                key = bytes([random.randint(0, 255) for _ in range(key_size)])
                plaintext = bytes([random.randint(0, 255) for _ in range(block_size)])
                
                try:
                    rijndael = Rijndael(block_size=block_size)
                    rijndael.key = key
                    
                    encrypted_result = bytearray(block_size)
                    rijndael.encrypt(plaintext, encrypted_result)
                    encrypted = bytes(encrypted_result)
                    
                    decrypted_result = bytearray(block_size)
                    rijndael.decrypt(encrypted, decrypted_result)
                    decrypted = bytes(decrypted_result)
                    
                    if plaintext == decrypted:
                        print(f"    Test {i+1}: ✓ PASS")
                    else:
                        print(f"    Test {i+1}: ✗ FAIL")
                        print(f"      Original:  {plaintext.hex()}")
                        print(f"      Decrypted: {decrypted.hex()}")
                        all_passed = False
                        
                except Exception as e:
                    print(f"    Test {i+1}: ✗ FAIL - {e}")
                    all_passed = False
    
    if all_passed:
        print("\nAll round-trip tests PASSED! ✓")
    else:
        print("\nSome round-trip tests FAILED! ✗")
    
    return all_passed


def test_file_encryption():
    """Test file encryption/decryption with Rijndael (AES mode)"""
    print("\nFile Encryption Test")
    print("=" * 60)
    
    project_root = Path(__file__).parent.parent
    input_file = project_root / "data" / "hamster.png"
    output_dir = project_root / "data" / "output"
    encrypted_file = output_dir / "hamster_rijndael_encrypted.bin"
    decrypted_file = output_dir / "hamster_rijndael_decrypted.png"
    
    if not input_file.exists():
        print(f"⚠ Test file not found: {input_file}")
        return False
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    key_128 = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
    key_192 = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    key_256 = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    iv = bytes.fromhex('1234567890ABCDEF1234567890ABCDEF')
    
    test_configs = [
        ("AES-128, ECB with PKCS7", key_128, Cipher_Mode.ECB, Padding_Mode.PKCS7, 16),
        ("AES-128, CBC with PKCS7", key_128, Cipher_Mode.CBC, Padding_Mode.PKCS7, 16),
        ("AES-192, CBC with PKCS7", key_192, Cipher_Mode.CBC, Padding_Mode.PKCS7, 16),
        ("AES-256, CBC with PKCS7", key_256, Cipher_Mode.CBC, Padding_Mode.PKCS7, 16),
        ("AES-128, PCBC with ANSI_X_923", key_128, Cipher_Mode.PCBC, Padding_Mode.ANSI_X_923, 16),
        ("AES-128, CFB (no padding)", key_128, Cipher_Mode.CFB, Padding_Mode.Zeros, 16),
        ("AES-128, OFB (no padding)", key_128, Cipher_Mode.OFB, Padding_Mode.Zeros, 16),
        ("AES-128, CTR (no padding)", key_128, Cipher_Mode.CTR, Padding_Mode.Zeros, 16),
    ]
    
    all_passed = True
    original_data = input_file.read_bytes()
    
    for name, key, mode, padding, block_size in test_configs:
        print(f"\nTesting: {name}")
        
        try:
            rijndael = Rijndael(block_size=block_size)
            cipher = FileCipher(rijndael, mode, padding, iv, block_size=block_size)
            cipher.key = key
            
            cipher.encrypt_file(input_file, encrypted_file)
            
            rijndael2 = Rijndael(block_size=block_size)
            cipher2 = FileCipher(rijndael2, mode, padding, iv, block_size=block_size)
            cipher2.key = key
            cipher2.decrypt_file(encrypted_file, decrypted_file)
            
            decrypted_data = decrypted_file.read_bytes()
            
            if original_data == decrypted_data:
                print(f"  ✓ PASS - File integrity preserved")
                print(f"  Original size: {len(original_data)} bytes")
                print(f"  Encrypted size: {encrypted_file.stat().st_size} bytes")
            else:
                print(f"  ✗ FAIL - File corrupted")
                print(f"  Original size: {len(original_data)} bytes")
                print(f"  Decrypted size: {len(decrypted_data)} bytes")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
    
    if all_passed:
        print("\n✓ All file encryption tests PASSED!")
    else:
        print("\n✗ Some file encryption tests FAILED!")
    
    return all_passed


def test_bytes_encryption():
    """Test bytes encryption/decryption with different modes"""
    print("\nBytes Encryption Test")
    print("=" * 60)
    
    key_128 = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210')
    key_192 = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210')
    key_256 = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210')
    iv = bytes.fromhex('0F1E2D3C4B5A69780F1E2D3C4B5A6978')
    
    test_data = b"Hello, Rijndael/AES encryption! This is a test message for the cipher."
    
    test_configs = [
        ("AES-128, ECB + PKCS7", key_128, Cipher_Mode.ECB, Padding_Mode.PKCS7, 16),
        ("AES-128, CBC + PKCS7", key_128, Cipher_Mode.CBC, Padding_Mode.PKCS7, 16),
        ("AES-192, CBC + PKCS7", key_192, Cipher_Mode.CBC, Padding_Mode.PKCS7, 16),
        ("AES-256, CBC + PKCS7", key_256, Cipher_Mode.CBC, Padding_Mode.PKCS7, 16),
        ("AES-128, OFB", key_128, Cipher_Mode.OFB, Padding_Mode.Zeros, 16),
        ("AES-128, CTR", key_128, Cipher_Mode.CTR, Padding_Mode.Zeros, 16),
    ]
    
    all_passed = True
    
    for name, key, mode, padding, block_size in test_configs:
        print(f"\nTesting: {name}")
        
        try:
            rijndael = Rijndael(block_size=block_size)
            cipher = FileCipher(rijndael, mode, padding, iv, block_size=block_size)
            cipher.key = key
            
            encrypted = cipher.encrypt_bytes(test_data)
            decrypted = cipher.decrypt_bytes(encrypted)
            
            if test_data == decrypted:
                print(f"  ✓ PASS")
                print(f"  Original: {test_data[:40]}...")
                print(f"  Encrypted length: {len(encrypted)} bytes")
            else:
                print(f"  ✗ FAIL - Data mismatch")
                print(f"  Expected: {test_data}")
                print(f"  Got: {decrypted}")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
    
    return all_passed


def test_key_validation():
    """Test key validation"""
    print("\nKey Validation Test")
    print("=" * 40)
    
    rijndael = Rijndael(block_size=16)
    
    valid_keys = [
        (16, "128-bit key"),
        (24, "192-bit key"),
        (32, "256-bit key"),
    ]
    
    invalid_keys = [
        (8, "64-bit key (too short)"),
        (12, "96-bit key (invalid)"),
        (40, "320-bit key (too long)"),
    ]
    
    all_passed = True
    
    print("\nValid key sizes:")
    for size, name in valid_keys:
        try:
            rijndael.key = bytes([0] * size)
            print(f"  {name}: ✓ PASS")
        except Exception as e:
            print(f"  {name}: ✗ FAIL - {e}")
            all_passed = False
    
    print("\nInvalid key sizes (should raise exceptions):")
    for size, name in invalid_keys:
        try:
            rijndael.key = bytes([0] * size)
            print(f"  {name}: ✗ FAIL - Should have raised exception")
            all_passed = False
        except ValueError as e:
            print(f"  {name}: ✓ PASS - Correctly rejected")
        except Exception as e:
            print(f"  {name}: ✗ FAIL - Wrong exception: {e}")
            all_passed = False
    
    return all_passed


if __name__ == '__main__':
    try:
        vectors_passed = test_aes_vectors()
        
        variable_blocks_passed = test_variable_block_sizes()
        
        roundtrip_passed = test_round_trip()
        
        key_validation_passed = test_key_validation()
        
        
        file_passed = test_file_encryption()
        
        bytes_passed = test_bytes_encryption()
        
        all_passed = (
            vectors_passed and 
            variable_blocks_passed and
            roundtrip_passed and 
            key_validation_passed and 
            file_passed and 
            bytes_passed
        )
        
        print("\n" + "=" * 60)
        if all_passed:
            print(" All Rijndael tests completed successfully!")
            sys.exit(0)
        else:
            print(" Some Rijndael tests failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

#!/usr/bin/env python3
"""
DES Demo Script
Tests the DES implementation with known test vectors from FIPS 46-3
"""

import sys
import os
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from cryptography.des_implementation import Des
from cryptography.demonstrator import FileCipher
from cryptography.modes import Cipher_Mode
from cryptography.paddings import Padding_Mode

def test_des_vectors():
    """Test DES with known test vectors from FIPS 46-3"""
    
    # Test vectors from FIPS 46-3 Appendix A
    test_cases = [
        {
            'key': bytes.fromhex('0000000000000000'),
            'plaintext': bytes.fromhex('0000000000000000'),
            'ciphertext': bytes.fromhex('8CA64DE9C1B123A7')
        },
        {
            'key': bytes.fromhex('FFFFFFFFFFFFFFFF'),
            'plaintext': bytes.fromhex('FFFFFFFFFFFFFFFF'),
            'ciphertext': bytes.fromhex('7359B2163E4EDC58')
        },
        {
            'key': bytes.fromhex('3000000000000000'),
            'plaintext': bytes.fromhex('1000000000000001'),
            'ciphertext': bytes.fromhex('958E6E627A05557B')
        },
        {
            'key': bytes.fromhex('1111111111111111'),
            'plaintext': bytes.fromhex('1111111111111111'),
            'ciphertext': bytes.fromhex('F40379AB9E0EC533')
        },
        {
            'key': bytes.fromhex('0123456789ABCDEF'),
            'plaintext': bytes.fromhex('1111111111111111'),
            'ciphertext': bytes.fromhex('17668DFC7292532D')
        }
    ]
    
    des = Des()
    
    print("DES Test Vectors (FIPS 46-3)")
    print("=" * 50)
    
    all_passed = True
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Key:        {test['key'].hex().upper()}")
        print(f"Plaintext:  {test['plaintext'].hex().upper()}")
        print(f"Expected:   {test['ciphertext'].hex().upper()}")
        
        # Test encryption
        des.key = test['key']
        encrypted_result = bytearray(8)
        des.encrypt(test['plaintext'], encrypted_result)
        encrypted = bytes(encrypted_result)
        
        print(f"Encrypted:  {encrypted.hex().upper()}")
        
        # Test decryption
        decrypted_result = bytearray(8)
        des.decrypt(encrypted, decrypted_result)
        decrypted = bytes(decrypted_result)
        
        print(f"Decrypted:  {decrypted.hex().upper()}")
        
        # Check results
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
    
    print("\n" + "=" * 50)
    if all_passed:
        print("All tests PASSED! ✓")
    else:
        print("Some tests FAILED! ✗")
    
    return all_passed

def test_round_trip():
    """Test encrypt/decrypt round-trip with random data"""
    import random
    
    print("\nRound-trip Test")
    print("=" * 30)
    
    des = Des()
    
    # Test with random keys and data
    for i in range(5):
        key = bytes([random.randint(0, 255) for _ in range(8)])
        plaintext = bytes([random.randint(0, 255) for _ in range(8)])
        
        des.key = key
        
        # Encrypt
        encrypted_result = bytearray(8)
        des.encrypt(plaintext, encrypted_result)
        encrypted = bytes(encrypted_result)
        
        # Decrypt
        decrypted_result = bytearray(8)
        des.decrypt(encrypted, decrypted_result)
        decrypted = bytes(decrypted_result)
        
        if plaintext == decrypted:
            print(f"Test {i+1}: ✓ PASS")
        else:
            print(f"Test {i+1}: ✗ FAIL")
            print(f"  Original: {plaintext.hex()}")
            print(f"  Decrypted: {decrypted.hex()}")
            return False
    
    print("All round-trip tests PASSED! ✓")
    return True

def test_file_encryption():
    """Test file encryption/decryption with DES"""
    print("\nFile Encryption Test")
    print("=" * 50)
    
    project_root = Path(__file__).parent.parent
    input_file = project_root / "data" / "hamster.png"
    output_dir = project_root / "data" / "output"
    encrypted_file = output_dir / "hamster_encrypted.bin"
    decrypted_file = output_dir / "hamster_decrypted.png"
    
    if not input_file.exists():
        print(f"⚠ Test file not found: {input_file}")
        return False
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    key = bytes.fromhex('0123456789ABCDEF')
    iv = bytes.fromhex('1234567890ABCDEF')
    
    test_configs = [
        ("ECB with PKCS7", Cipher_Mode.ECB, Padding_Mode.PKCS7),
        ("CBC with PKCS7", Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("PCBC with ANSI_X_923", Cipher_Mode.PCBC, Padding_Mode.ANSI_X_923),
        ("CFB (no padding)", Cipher_Mode.CFB, Padding_Mode.Zeros),
        ("OFB (no padding)", Cipher_Mode.OFB, Padding_Mode.Zeros),
        ("CTR (no padding)", Cipher_Mode.CTR, Padding_Mode.Zeros),
    ]
    
    all_passed = True
    original_data = input_file.read_bytes()
    
    for name, mode, padding in test_configs:
        print(f"\nTesting: {name}")
        
        try:
            des = Des()
            cipher = FileCipher(des, mode, padding, iv)
            cipher.key = key
            
            cipher.encrypt_file(input_file, encrypted_file)
            
            cipher2 = FileCipher(Des(), mode, padding, iv)
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
            all_passed = False
    
    if all_passed:
        print("\n✓ All file encryption tests PASSED!")
    else:
        print("\n✗ Some file encryption tests FAILED!")
    
    return all_passed

def test_bytes_encryption():
    """Test bytes encryption/decryption with different modes"""
    print("\nBytes Encryption Test")
    print("=" * 50)
    
    key = bytes.fromhex('FEDCBA9876543210')
    iv = bytes.fromhex('0F1E2D3C4B5A6978')
    
    test_data = b"Hello, DES encryption! This is a test message."
    
    test_configs = [
        ("ECB + PKCS7", Cipher_Mode.ECB, Padding_Mode.PKCS7),
        ("CBC + PKCS7", Cipher_Mode.CBC, Padding_Mode.PKCS7),
        ("OFB", Cipher_Mode.OFB, Padding_Mode.Zeros),
        ("CTR", Cipher_Mode.CTR, Padding_Mode.Zeros),
    ]
    
    all_passed = True
    
    for name, mode, padding in test_configs:
        print(f"\nTesting: {name}")
        
        try:
            des = Des()
            cipher = FileCipher(des, mode, padding, iv)
            cipher.key = key
            
            encrypted = cipher.encrypt_bytes(test_data)
            decrypted = cipher.decrypt_bytes(encrypted)
            
            if test_data == decrypted:
                print(f"  ✓ PASS")
                print(f"  Original: {test_data[:30]}...")
                print(f"  Encrypted length: {len(encrypted)} bytes")
            else:
                print(f"  ✗ FAIL - Data mismatch")
                print(f"  Expected: {test_data}")
                print(f"  Got: {decrypted}")
                all_passed = False
                
        except Exception as e:
            print(f"  ✗ FAIL - Exception: {e}")
            all_passed = False
    
    return all_passed

if __name__ == '__main__':
    try:
        # Run test vectors
        vectors_passed = test_des_vectors()
        
        # Run round-trip tests
        roundtrip_passed = test_round_trip()
        
        # Run file encryption tests
        file_passed = test_file_encryption()
        
        # Run bytes encryption tests
        bytes_passed = test_bytes_encryption()
        
        if vectors_passed and roundtrip_passed and file_passed and bytes_passed:
            print("\n" + "=" * 50)
            print(" All DES tests completed successfully!")
            sys.exit(0)
        else:
            print("\n" + "=" * 50)
            print(" Some DES tests failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
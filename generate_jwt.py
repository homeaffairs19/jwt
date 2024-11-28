import base64
import json
import hashlib
import hmac
import datetime

def generate_jwt(secret, algorithm='HS256'):
    """
    Generates a JWT token with the specified algorithm (HS256, HS384, or HS512).
    """
    # JWT header
    header = {
        "alg": algorithm,
        "typ": "JWT"
    }

    # JWT payload
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": int(datetime.datetime.utcnow().timestamp())  # Convert to integer
    }

    #  Base64 URL encode the header
    header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")

    #  Base64 URL encode the payload
    payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    #  ADD the header and payload with a dot (.)
    message = f"{header_encoded}.{payload_encoded}"

    #  Choose the hash function based on the algorithm
    if algorithm == "HS256":
        hash_algorithm = hashlib.sha256
    elif algorithm == "HS384":
        hash_algorithm = hashlib.sha384
    elif algorithm == "HS512":
        hash_algorithm = hashlib.sha512
    else:
        raise ValueError("Unsupported algorithm")

    #  Create the HMAC signature
    signature = hmac.new(secret.encode(), message.encode(), hash_algorithm).digest()

    #  Base64 URL encode the signature
    signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    #  Final JWT Token
    jwt_token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"

    return jwt_token


# 
if __name__ == "__main__":
    secret = "harsh"  # The secret 

    
    jwt_hs256 = generate_jwt(secret, "HS256")
    jwt_hs384 = generate_jwt(secret, "HS384")
    jwt_hs512 = generate_jwt(secret, "HS512")

    print(f"Generated JWT (HS256): {jwt_hs256}")
    print(f"Generated JWT (HS384): {jwt_hs384}")
    print(f"Generated JWT (HS512): {jwt_hs512}")

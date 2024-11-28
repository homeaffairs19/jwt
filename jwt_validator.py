import jwt
import base64

SUPPORTED_ALGORITHMS = ['HS256', 'HS384', 'HS512']

def validateToken(token):
   
    if not validateGeneralJwtFormat(token):
        return False, ''
    
    if not validateHmacAlgorithmHeader(token):
        return False, ''
    
    algorithm = decode_header(token)['alg']
    return True, algorithm

def validateGeneralJwtFormat(token):
   
    parts = token.split('.')
    return len(parts) == 3 and all(parts)

def decode_header(token):
    
    parts = token.split('.')
    decoded_header = base64.urlsafe_b64decode(parts[0] + "==")
    return jwt.api_jws.get_unverified_header(token)

def validateHmacAlgorithmHeader(token):
   
    decoded_header = decode_header(token)
    if not decoded_header or decoded_header.get('typ') != 'JWT':
        return False
    return decoded_header.get('alg') in SUPPORTED_ALGORITHMS

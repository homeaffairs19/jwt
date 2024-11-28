import pytest
from jwt_validator import validateToken, validateGeneralJwtFormat, validateHmacAlgorithmHeader


validHS256Token = (
    '#replace with your Token'
)
validHS384Token = (
    '#replace with your Token'
)
validHS512Token = (
    ' #replace with your Token'
)
invalidFormatToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Imp3dC1jcmFja2VyIn0'

# Test validateToken with valid tokens for each algorithm
def test_validate_token_with_valid_HS256():
    is_valid, algorithm = validateToken(validHS256Token)
    assert is_valid == True
    assert algorithm == 'HS256'

def test_validate_token_with_valid_HS384():
    is_valid, algorithm = validateToken(validHS384Token)
    assert is_valid == True
    assert algorithm == 'HS384'

def test_validate_token_with_valid_HS512():
    is_valid, algorithm = validateToken(validHS512Token)
    assert is_valid == True
    assert algorithm == 'HS512'

# Test validateToken with an invalid token format
def test_validate_token_with_invalid_format():
    is_valid, _ = validateToken(invalidFormatToken)
    assert is_valid == False

# Test validateGeneralJwtFormat for valid tokens
def test_validate_general_jwt_format_with_valid_HS256():
    assert validateGeneralJwtFormat(validHS256Token) == True

def test_validate_general_jwt_format_with_valid_HS384():
    assert validateGeneralJwtFormat(validHS384Token) == True

def test_validate_general_jwt_format_with_valid_HS512():
    assert validateGeneralJwtFormat(validHS512Token) == True

# Test validateGeneralJwtFormat with an invalid token format
def test_validate_general_jwt_format_with_invalid_format():
    assert validateGeneralJwtFormat(invalidFormatToken) == False

# Test validateHmacAlgorithmHeader for valid tokens
def test_validate_hmac_algorithm_header_with_HS256():
    is_valid = validateHmacAlgorithmHeader(validHS256Token)
    assert is_valid == True

def test_validate_hmac_algorithm_header_with_HS384():
    is_valid = validateHmacAlgorithmHeader(validHS384Token)
    assert is_valid == True

def test_validate_hmac_algorithm_header_with_HS512():
    is_valid = validateHmacAlgorithmHeader(validHS512Token)
    assert is_valid == True

# Test validateHmacAlgorithmHeader with invalid algorithm
def test_validate_hmac_algorithm_header_with_invalid_algorithm():
    # Example token with an unsupported algorithm (e.g., RS256)
    invalid_algo_token = (
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJSUzI1NmluT1RBIiwibmFtZSI6IkpvaG4gRG9lIn0.'
        'ICV6gy7CDKPHMGJxV80nDZ7Vxe0ciqyzXD_Hr4mTDrdTyi6fNleYAyhEZq2J29HSI5bhWnJyOBzg2bssBUKMYlC2Sr8WFUas5MAKIr2Uh_tZHDsrCxggQuaHpF4aGCFZ1Qc0rrDXvKLuk1Kzrfw1bQbqH6xTmg2kWQuSGuTlbTbDhyhRfu1WDs-Ju9XnZV-FBRgHJDdTARq1b4kuONgBP430wJmJ6s9yl3POkHIdgV-Bwlo6aZluophoo5XWPEHQIpCCgDm3-kTN_uIZMOHs2KRdb6Px-VN19A5BYDXlUBFOo-GvkCBZCgmGGTlHF_cWlDnoA9XTWWcIYNyUI4PXNw'
    )
    is_valid = validateHmacAlgorithmHeader(invalid_algo_token)
    assert is_valid == False

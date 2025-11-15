"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 


from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime

def load_certificate(cert_path):
    """Load X.509 certificate from PEM file"""
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_private_key(key_path):
    """Load RSA private key from PEM file"""
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def validate_certificate(cert, ca_cert):
    """
    Validate certificate against CA
    Returns: (True, None) if valid, (False, error_msg) if invalid
    """
    # 1. Check expiry
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False, "BAD_CERT: Certificate expired or not yet valid"
    
    # 2. Verify signature chain (issued by trusted CA)
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except InvalidSignature:
        return False, "BAD_CERT: Invalid signature chain"
    except Exception as e:
        return False, f"BAD_CERT: Verification failed - {str(e)}"
    
    # 3. Check issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        return False, "BAD_CERT: Issuer mismatch"
    
    return True, None

def get_cert_fingerprint(cert):
    """Get SHA-256 fingerprint of certificate"""
    from cryptography.hazmat.primitives import hashes
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()

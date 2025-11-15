"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64

def sign_message(data_bytes, private_key):
    """
    Sign data with RSA private key
    Returns: base64-encoded signature
    """
    signature = private_key.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data_bytes, signature_b64, public_key):
    """
    Verify RSA signature
    Returns: True if valid, False otherwise
    """
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

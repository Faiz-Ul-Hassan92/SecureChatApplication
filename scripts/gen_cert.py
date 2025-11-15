"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import sys

def load_ca():
    """Load CA private key and certificate"""
    with open("certs/ca-key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open("certs/ca-cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert

def generate_entity_cert(entity_name, common_name):
    """Generate certificate for server or client"""
    
    # 1. Load CA
    ca_key, ca_cert = load_ca()
    
    # 2. Generate entity's private key
    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # 3. Create certificate signed by CA
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad Capital Territory"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject) 
        .public_key(entity_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())  # Signed by CA's private key
    )
    
    # 4. Save entity's private key and certificate
    key_path = f"certs/{entity_name}-key.pem"
    cert_path = f"certs/{entity_name}-cert.pem"
    
    with open(key_path, "wb") as f:
        f.write(entity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"✓ {entity_name} private key: {key_path}")
    print(f"✓ {entity_name} certificate: {cert_path}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python gen_cert.py <entity> <common_name>")
        print("Example: python gen_cert.py server localhost")
        print("Example: python gen_cert.py client client-user")
        sys.exit(1)
    
    entity = sys.argv[1]
    cn = sys.argv[2]
    generate_entity_cert(entity, cn)

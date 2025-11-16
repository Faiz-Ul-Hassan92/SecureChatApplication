# scripts/gen_fake_cert.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def generate_fake_cert():
    # Generate keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Self-sign (no CA signature!)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "fake-client"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # Self-signed
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())  # Signed by itself, not CA
    )
    
    # Save
    with open("certs/fake-client-key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open("certs/fake-client-cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("✓ Fake certificate created")

if __name__ == "__main__":
    generate_fake_cert()
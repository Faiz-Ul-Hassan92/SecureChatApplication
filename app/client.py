"""Client skeleton — plain TCP; no TLS. See assignment spec."""


import socket
import json
import secrets
import hashlib
import time
import base64
from getpass import getpass
from crypto.pki import load_certificate, load_private_key, validate_certificate, get_cert_fingerprint
from crypto.dh import generate_keypair, compute_shared_secret, derive_aes_key, DH_GENERATOR, DH_PRIME
from crypto.aes import encrypt_aes, decrypt_aes
from crypto.sign import sign_message, verify_signature
from common.protocol import ProtocolMessage
from storage.transcript import Transcript
from cryptography.hazmat.primitives import serialization

class SecureChatClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.client_cert = load_certificate('../scripts/certs/fake-client-cert.pem')
        self.client_key = load_private_key('../scripts/certs/fake-client-key.pem')
        self.ca_cert = load_certificate('../scripts/certs/ca-cert.pem')
        self.session_key = None
        self.server_cert = None
        self.transcript = None
        self.seqno = 0
        
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[CLIENT] Connected to {self.host}:{self.port}")
        
        try:
            # Phase 1: Control Plane
            if not self.control_plane():
                return
            
            # Phase 2: Key Agreement
            if not self.key_agreement():
                return
            
            # Phase 3: Data Plane
            self.data_plane()
            
            # Phase 4: Teardown
            self.teardown()
            
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            self.sock.close()
    
    def control_plane(self):
        """Certificate exchange and authentication"""
        # Send client hello
        client_cert_pem = self.client_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        hello_msg = ProtocolMessage.create_hello(client_cert_pem, nonce)
        self.sock.send(hello_msg.encode())
        
        # Receive server hello
        data = self.sock.recv(4096).decode()
        msg = ProtocolMessage.parse(data)
        
        if msg.get('error'):
            print(f"[ERROR] {msg['error']}")
            return False
        
        # Validate server certificate
        from cryptography import x509
        server_cert_pem = msg['server_cert']
        self.server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode())
        
        valid, error = validate_certificate(self.server_cert, self.ca_cert)
        if not valid:
            print(f"[ERROR] {error}")
            return False
        
        print("[OK] Server certificate validated")
        
        # Receive server DH for temp encryption
        dh_data = self.sock.recv(4096).decode()
        dh_msg = ProtocolMessage.parse(dh_data)
        server_B = dh_msg['B']
        
        # Generate temp DH keypair
        temp_private, temp_public = generate_keypair()
        
        # Send client DH
        dh_client = ProtocolMessage.create_dh_client(DH_GENERATOR, DH_PRIME, temp_public)
        self.sock.send(dh_client.encode())
        
        # Derive temp key
        temp_secret = compute_shared_secret(server_B, temp_private)
        temp_key = derive_aes_key(temp_secret)
        
        # Registration or Login
        choice = input("[CLIENT] (R)egister or (L)ogin? ").strip().upper()
        
        if choice == 'R':
            return self.register(temp_key)
        elif choice == 'L':
            return self.login(temp_key)
        
        return False
    
    def register(self, key):
        email = input("Email: ")
        username = input("Username: ")
        password = getpass("Password: ")
        
        # Generate salt and hash
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        
        # Send registration
        reg_msg = ProtocolMessage.create_register(
            email, username, pwd_hash, base64.b64encode(salt).decode()
        )
        self.sock.send(reg_msg.encode())
        
        # Receive response
        response = ProtocolMessage.parse(self.sock.recv(4096).decode())
        print(f"[SERVER] {response['message']}")
        
        return response['status'] == 'success'
    
    def login(self, key):
        email = input("Email: ")
        
        # Request salt from server first
        salt_request = json.dumps({"type": "get_salt", "email": email})
        self.sock.send(salt_request.encode())
        
        salt_response = ProtocolMessage.parse(self.sock.recv(4096).decode())
        if salt_response.get('error'):
            print(f"[ERROR] {salt_response['error']}")
            return False
        
        salt = base64.b64decode(salt_response['salt'])
        
        password = getpass("Password: ")
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
        
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        login_msg = ProtocolMessage.create_login(email, pwd_hash, nonce)
        self.sock.send(login_msg.encode())
        
        response = ProtocolMessage.parse(self.sock.recv(4096).decode())
        print(f"[SERVER] {response['message']}")
        
        return response['status'] == 'success'
    
    def key_agreement(self):
        """Establish session key"""
        # Receive server DH
        dh_data = self.sock.recv(4096).decode()
        dh_msg = ProtocolMessage.parse(dh_data)
        server_B = dh_msg['B']
        
        # Generate DH keypair
        dh_private, dh_public = generate_keypair()
        
        # Send client DH
        dh_client = ProtocolMessage.create_dh_client(DH_GENERATOR, DH_PRIME, dh_public)
        self.sock.send(dh_client.encode())
        
        # Derive session key
        shared_secret = compute_shared_secret(server_B, dh_private)
        self.session_key = derive_aes_key(shared_secret)
        
        print("[OK] Session key established")
        
        # Initialize transcript
        self.transcript = Transcript(f'transcripts/client_{int(time.time())}.txt')
        return True
    
    def data_plane(self):
        """Encrypted chat"""
        print("[CHAT] Type messages (or 'exit' to quit):")
        
        while True:
            msg_text = input("You: ")
            
            if msg_text.lower() == 'exit':
                self.sock.send(json.dumps({"type": "exit"}).encode())
                break
            
            # Encrypt message
            ciphertext = encrypt_aes(msg_text, self.session_key)
            
            # Prepare message fields
            self.seqno += 1
            timestamp = int(time.time() * 1000)
            
            # Sign message
            hash_data = ProtocolMessage.compute_message_hash(self.seqno, timestamp, ciphertext)
            signature = sign_message(hash_data, self.client_key)
            
            # Send message
            msg_json = ProtocolMessage.create_message(self.seqno, timestamp, ciphertext, signature)
            self.sock.send(msg_json.encode())
            
            # Add to transcript
            peer_fp = get_cert_fingerprint(self.server_cert)
            self.transcript.add_entry(self.seqno, timestamp, ciphertext, signature, peer_fp)
    
    def teardown(self):
        """Generate session receipt"""
        if not self.transcript:
            return
        
        transcript_hash = self.transcript.compute_hash()
        signature = sign_message(transcript_hash.encode(), self.client_key)
        
        first_seq, last_seq = self.transcript.get_range()
        receipt = ProtocolMessage.create_receipt(
            "client", first_seq, last_seq, transcript_hash, signature
        )
        
        with open(f'receipts/client_{int(time.time())}.json', 'w') as f:
            f.write(receipt)
        
        print("[OK] Session receipt generated")

if __name__ == "__main__":
    client = SecureChatClient()
    client.connect()
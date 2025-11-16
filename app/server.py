"""Server skeleton — plain TCP; no TLS. See assignment spec."""


import socket
import json
import secrets
import hashlib
import time
import base64
from crypto.pki import load_certificate, load_private_key, validate_certificate, get_cert_fingerprint
from crypto.dh import generate_keypair, compute_shared_secret, derive_aes_key, DH_GENERATOR, DH_PRIME
from crypto.aes import encrypt_aes, decrypt_aes
from crypto.sign import sign_message, verify_signature
from common.protocol import ProtocolMessage
from storage.db import UserDB
from storage.transcript import Transcript


class SecureChatServer:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_cert = load_certificate('../scripts/certs/server-cert.pem')
        self.server_key = load_private_key('../scripts/certs/server-key.pem')
        self.ca_cert = load_certificate('../scripts/certs/ca-cert.pem')
        self.db = UserDB()
        self.session_key = None
        self.client_cert = None
        self.transcript = None
        self.seqno = 0
        
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(1)
        print(f"[SERVER] Listening on {self.host}:{self.port}")
        
        while True:
            conn, addr = sock.accept()
            print(f"[SERVER] Connection from {addr}")
            self.handle_client(conn)
            conn.close()
    
    def handle_client(self, conn):
        try:
            # Phase 1: Control Plane (Certificate Exchange)
            if not self.control_plane(conn):
                return
            
            # Phase 2: Key Agreement
            if not self.key_agreement(conn):
                return
            
            # Phase 3: Data Plane (Chat)
            self.data_plane(conn)
            
            # Phase 4: Teardown (Non-repudiation)
            self.teardown(conn)
            
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            self.db.close()
    
    def control_plane(self, conn):
        """Handle certificate exchange and authentication"""
        # Receive client hello
        data = conn.recv(4096).decode()
        msg = ProtocolMessage.parse(data)
        
        if msg['type'] != 'hello':
            print("[ERROR] Expected hello")
            return False
        
        # Load and validate client certificate
        from cryptography import x509
        client_cert_pem = msg['client_cert']
        self.client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode())
        
        valid, error = validate_certificate(self.client_cert, self.ca_cert)
        if not valid:
            print(f"[ERROR] {error}")
            conn.send(json.dumps({"error": error}).encode())
            return False
        
        print("[OK] Client certificate validated")
        
        # Send server hello
        server_cert_pem = self.server_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
        
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        response = ProtocolMessage.create_server_hello(server_cert_pem, nonce)
        conn.send(response.encode())
        
        # Temporary DH for registration/login encryption
        temp_dh_private, temp_dh_public = generate_keypair()
        dh_msg = ProtocolMessage.create_dh_server(temp_dh_public)
        conn.send(dh_msg.encode())
        
        # Receive client DH
        dh_client_data = conn.recv(4096).decode()
        dh_client_msg = ProtocolMessage.parse(dh_client_data)
        client_A = dh_client_msg['A']
        
        # Derive temp AES key
        temp_secret = compute_shared_secret(client_A, temp_dh_private)
        temp_key = derive_aes_key(temp_secret)
        
        # Receive first message (could be get_salt, register, or login)
        auth_data = conn.recv(4096).decode()
        auth_msg = ProtocolMessage.parse(auth_data)
        
        # Handle salt request for login
        if auth_msg['type'] == 'get_salt':
            user = self.db.get_user(auth_msg['email'])
            if not user:
                conn.send(json.dumps({"error": "User not found"}).encode())
                return False
            salt_b64 = base64.b64encode(user['salt']).decode()
            conn.send(json.dumps({"salt": salt_b64}).encode())
            
            # Now receive actual login
            auth_data = conn.recv(4096).decode()
            auth_msg = ProtocolMessage.parse(auth_data)
        
        if auth_msg['type'] == 'register': 
            return self.handle_register(conn, auth_msg, temp_key)
        elif auth_msg['type'] == 'login':
            return self.handle_login(conn, auth_msg, temp_key)
        
        return False
    
    def handle_register(self, conn, msg, key):
        email = msg['email']
        username = msg['username']
        pwd_hash_b64 = msg['pwd']
        salt_b64 = msg['salt']
        
        salt = base64.b64decode(salt_b64)
        pwd_hash = pwd_hash_b64
        
        success, message = self.db.register_user(email, username, salt, pwd_hash)
        conn.send(json.dumps({"status": "success" if success else "error", "message": message}).encode())
        return success
    
    def handle_login(self, conn, msg, key):
        email = msg['email']
        pwd_hash_client = msg['pwd']
        
        user = self.db.get_user(email)
        if not user:
            conn.send(json.dumps({"status": "error", "message": "User not found"}).encode())
            return False
        
        # Verify password hash
        if user['pwd_hash'] != pwd_hash_client:
            conn.send(json.dumps({"status": "error", "message": "Invalid credentials"}).encode())
            return False
        
        print(f"[OK] User {user['username']} logged in")
        conn.send(json.dumps({"status": "success", "message": "Login successful"}).encode())
        return True
    
    def key_agreement(self, conn):
        """Establish session key via DH"""
        # Generate DH keypair
        dh_private, dh_public = generate_keypair()
        
        # Send DH parameters
        dh_msg = ProtocolMessage.create_dh_server(dh_public)
        conn.send(dh_msg.encode())
        
        # Receive client DH
        dh_data = conn.recv(4096).decode()
        dh_msg = ProtocolMessage.parse(dh_data)
        client_A = dh_msg['A']
        
        # Compute shared secret and derive AES key
        shared_secret = compute_shared_secret(client_A, dh_private)
        self.session_key = derive_aes_key(shared_secret)
        
        print("[OK] Session key established")
        
        # Initialize transcript
        self.transcript = Transcript(f'transcripts/server_{int(time.time())}.txt')
        return True
    
    def data_plane(self, conn):
        """Handle encrypted message exchange"""
        print("[CHAT] Session started. Type messages...")
        
        while True:
            # Receive message
            data = conn.recv(4096)
            if not data:
                break
            
            msg = ProtocolMessage.parse(data.decode())
            
            if msg['type'] == 'msg':
                if not self.process_message(msg):
                    conn.send(json.dumps({"error": "SIG_FAIL or REPLAY"}).encode())
                    continue
            elif msg['type'] == 'exit':
                break
            
            # Send response (echo for now)
            # In real implementation, read from console in separate thread
    
    def process_message(self, msg):
        """Verify and decrypt incoming message"""
        seqno = msg['seqno']
        timestamp = msg['ts']
        ciphertext = msg['ct']
        signature = msg['sig']
        
        # Replay protection
        if seqno <= self.seqno:
            print("[ERROR] REPLAY detected")
            return False
        
        # Verify signature
        hash_data = ProtocolMessage.compute_message_hash(seqno, timestamp, ciphertext)
        if not verify_signature(hash_data, signature, self.client_cert.public_key()):
            print("[ERROR] SIG_FAIL")
            return False
        
        # Decrypt
        plaintext = decrypt_aes(ciphertext, self.session_key)
        print(f"[CLIENT] {plaintext}")
        
        # Add to transcript
        peer_fp = get_cert_fingerprint(self.client_cert)
        self.transcript.add_entry(seqno, timestamp, ciphertext, signature, peer_fp)
        
        self.seqno = seqno
        return True
    
    def teardown(self, conn):
        """Generate and exchange session receipt"""
        if not self.transcript:
            return
        
        # Compute transcript hash
        transcript_hash = self.transcript.compute_hash()
        
        # Sign transcript hash
        signature = sign_message(transcript_hash.encode(), self.server_key)
        
        # Create receipt
        first_seq, last_seq = self.transcript.get_range()
        receipt = ProtocolMessage.create_receipt(
            "server", first_seq, last_seq, transcript_hash, signature
        )
        
        # Save receipt
        with open(f'receipts/server_{int(time.time())}.json', 'w') as f:
            f.write(receipt)
        
        print("[OK] Session receipt generated")

if __name__ == "__main__":
    from cryptography.hazmat.primitives import serialization
    server = SecureChatServer()
    server.start()

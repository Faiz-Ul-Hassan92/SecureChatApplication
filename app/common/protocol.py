"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 


import json
import hashlib

class ProtocolMessage:
    """Handle protocol message creation and parsing"""
    
    @staticmethod
    def create_hello(cert_pem, nonce):
        return json.dumps({
            "type": "hello",
            "client_cert": cert_pem,
            "nonce": nonce
        })
    
    @staticmethod
    def create_server_hello(cert_pem, nonce):
        return json.dumps({
            "type": "server_hello",
            "server_cert": cert_pem,
            "nonce": nonce
        })
    
    @staticmethod
    def create_register(email, username, pwd_hash, salt):
        return json.dumps({
            "type": "register",
            "email": email,
            "username": username,
            "pwd": pwd_hash,
            "salt": salt
        })
    
    @staticmethod
    def create_login(email, pwd_hash, nonce):
        return json.dumps({
            "type": "login",
            "email": email,
            "pwd": pwd_hash,
            "nonce": nonce
        })
    
    @staticmethod
    def create_dh_client(g, p, A):
        return json.dumps({
            "type": "dh_client",
            "g": g,
            "p": p,
            "A": A
        })
    
    @staticmethod
    def create_dh_server(B):
        return json.dumps({
            "type": "dh_server",
            "B": B
        })
    
    @staticmethod
    def create_message(seqno, timestamp, ciphertext, signature):
        return json.dumps({
            "type": "msg",
            "seqno": seqno,
            "ts": timestamp,
            "ct": ciphertext,
            "sig": signature
        })
    
    @staticmethod
    def create_receipt(peer, first_seq, last_seq, transcript_hash, signature):
        return json.dumps({
            "type": "receipt",
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": signature
        })
    
    @staticmethod
    def parse(json_str):
        """Parse JSON message"""
        return json.loads(json_str)
    
    @staticmethod
    def compute_message_hash(seqno, timestamp, ciphertext):
        """Compute SHA-256(seqno || ts || ct) for signing"""
        data = f"{seqno}{timestamp}{ciphertext}".encode('utf-8')
        return hashlib.sha256(data).digest()

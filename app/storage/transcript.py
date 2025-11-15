"""Append-only transcript + TranscriptHash helpers.""" 


import hashlib
import os

class Transcript:
    def __init__(self, filename):
        self.filename = filename
        self.entries = []
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    def add_entry(self, seqno, timestamp, ciphertext, signature, peer_fingerprint):
        """Add message to transcript"""
        entry = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_fingerprint}\n"
        self.entries.append(entry)
        
        # Append to file
        with open(self.filename, 'a') as f:
            f.write(entry)
    
    def compute_hash(self):
        """Compute SHA-256 of entire transcript"""
        data = ''.join(self.entries).encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    def get_range(self):
        """Return (first_seq, last_seq)"""
        if not self.entries:
            return 0, 0
        first = int(self.entries[0].split('|')[0])
        last = int(self.entries[-1].split('|')[0])
        return first, last

"""MySQL users table + salted hashing (no chat storage).""" 


import mysql.connector
import os

class UserDB:
    def __init__(self):
        self.conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",  # Your MySQL password
            database="securechat"
        )
        self.cursor = self.conn.cursor()
    
    def register_user(self, email, username, salt, pwd_hash):
        """Register new user"""
        try:
            query = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            self.cursor.execute(query, (email, username, salt, pwd_hash))
            self.conn.commit()
            return True, "Registration successful"
        except mysql.connector.IntegrityError:
            return False, "Email or username already exists"
    
    def get_user(self, email):
        """Get user by email"""
        query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
        self.cursor.execute(query, (email,))
        result = self.cursor.fetchone()
        if result:
            return {
                'username': result[0],
                'salt': result[1],
                'pwd_hash': result[2]
            }
        return None
    
    def close(self):
        self.cursor.close()
        self.conn.close()
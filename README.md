Secure-Chat Application


An attempt to mimic chat applications using secure message transactions.

- Establishd a Certificate Authority as an issuer of local certificates for server and client.
- Implemented deffi-Hellman for Key Exchange for symmetric message encryption.
- RSA key pairs for signatures to establish Non-repudiation.
- SeqNos Along timestamps for each message to deter replay attacks by MiTM.
- MySQL database to store users and their salted hash passwords.

A complete flow of applications working is available in the report document.

Its a mini chat application, one user can connect to the server and send messages that will be logged on the command line of the server. The goal was to implement secure message transaction not user management for this project.

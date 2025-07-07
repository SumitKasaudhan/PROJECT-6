# Secure Chat Application

A Python-based secure messaging application that enables end-to-end encrypted text communication between two users. This project demonstrates the implementation of cryptographic principles for secure communications.

## Features

- **End-to-End Encryption**: All messages are encrypted using strong cryptographic algorithms
- **RSA Key Exchange**: Secure exchange of encryption keys
- **AES-256 Encryption**: Industry-standard symmetric encryption for messages
- **User-Friendly GUI**: Built with Tkinter for easy interaction
- **Chat History**: Option to save encrypted conversations
- **Connection Flexibility**: Works as both server (host) and client (join)

## Security Implementation

1. **Key Exchange Protocol**:
   - RSA-2048 asymmetric encryption for secure key exchange
   - Unique key pair generated for each session

2. **Message Encryption**:
   - AES-256 symmetric encryption in CBC mode
   - Unique session key for each conversation
   - Messages are padded according to PKCS#7

3. **Security Features**:
   - No plaintext data transmitted after initial key exchange
   - New encryption keys for each session
   - Secure disconnection handling

## Requirements

- Python 3.6 or higher
- PyCryptodome library
- Tkinter (usually comes with Python)

## Installation

1. Ensure you have Python installed
2. Install the required PyCryptodome library:
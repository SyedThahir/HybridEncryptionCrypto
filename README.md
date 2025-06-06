# Cryptography System with GUI

A comprehensive cryptographic system with a graphical user interface that implements multiple encryption algorithms and key management features.

## Features

- **Product Cipher Implementation**
  - Combines Affine Cipher and Columnar Transposition Cipher
  - Includes performance timing measurements
  - Preserves case sensitivity in text

- **AES (Advanced Encryption Standard)**
  - Secure key generation
  - Encryption and decryption using CBC mode
  - Base64 encoding for key and ciphertext representation

- **RSA Key Management**
  - 2048-bit RSA key pair generation
  - Public/Private key infrastructure
  - Secure key exchange mechanism

- **Error Analysis**
  - Bit error introduction for testing
  - Error logging and visualization
  - Corruption analysis capabilities

## Requirements

```python
cryptography>=3.4.7
tkinter (comes with Python)
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/SyedThahir/HybridEncryptionCrypto.git
cd cryptography
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python GUI_Crypto.py
```

The GUI provides several sections:

1. **Product Cipher Section**
   - Enter plaintext
   - Encrypt/Decrypt using combined Affine and Columnar Transposition ciphers
   - View encryption/decryption timing statistics

2. **Key Management Section**
   - Generate AES keys
   - Generate RSA key pairs
   - Encrypt/Decrypt AES keys using RSA

3. **Error Analysis**
   - Introduce bit errors
   - View corruption effects
   - Analyze error propagation

## Security Notes

- This implementation is for educational purposes
- The AES implementation uses CBC mode with random IV
- RSA implementation uses OAEP padding with SHA-256
- Key sizes: AES (128-bit), RSA (2048-bit)

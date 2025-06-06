import tkinter as tk
from tkinter import messagebox
import time, base64, os, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Utility function for generating styles
default_font = ("Helvetica", 12)
button_font = ("Helvetica", 12, "bold")

root = tk.Tk()
root.title("Cryptography Group P System")
root.geometry("900x750")
root.configure(bg="#f0f8ff")  # Light Blue background for the main window

# Affine Cipher Functions
def affine_encrypt(text, a=5, b=8):
    """Encrypt text using Affine Cipher while preserving case."""
    encrypted = ''
    for char in text:
        if char.isupper():
            encrypted += chr(((a * (ord(char) - ord('A')) + b) % 26) + ord('A'))
        elif char.islower():
            encrypted += chr(((a * (ord(char) - ord('a')) + b) % 26) + ord('a'))
        else:
            encrypted += char
    return encrypted

def affine_decrypt(ciphertext, a=5, b=8):
    """Decrypt text using Affine Cipher while preserving case."""
    a_inv = pow(a, -1, 26)
    decrypted = ''
    for char in ciphertext:
        if char.isupper():
            decrypted += chr(((a_inv * ((ord(char) - ord('A')) - b)) % 26) + ord('A'))
        elif char.islower():
            decrypted += chr(((a_inv * ((ord(char) - ord('a')) - b)) % 26) + ord('a'))
        else:
            decrypted += char
    return decrypted


# Columnar Transposition Cipher Functions
def columnar_transpose_encrypt(text, key=4):
    """Encrypt text using Columnar Transposition Cipher."""
    columns = [''] * key
    for i, char in enumerate(text):
        columns[i % key] += char
    return ''.join(columns)

def columnar_transpose_decrypt(ciphertext, key=4):
    """Decrypt text using Columnar Transposition Cipher."""
    num_full_cols = len(ciphertext) // key
    num_extra_chars = len(ciphertext) % key
    columns = [''] * key

    index = 0
    for i in range(key):
        length = num_full_cols + (1 if i < num_extra_chars else 0)
        columns[i] = ciphertext[index:index + length]
        index += length

    decrypted = ''.join(columns[i % key][i // key] for i in range(len(ciphertext)))
    return decrypted

# Product Cipher
def encrypt_with_product_cipher():
    """Encrypt using Affine + Columnar Transposition Cipher with precise timing."""
    plaintext = plaintext_text.get("1.0", "end-1c").strip()
    if not plaintext:
        messagebox.showerror("Error", "Plaintext is missing!")
        return

    iterations = 1000
    start_time = time.perf_counter()
    for _ in range(iterations):
        affine_encrypted = affine_encrypt(plaintext)
        final_encryption = columnar_transpose_encrypt(affine_encrypted)
    encryption_time = (time.perf_counter() - start_time) / iterations

    ciphertext_text.delete("1.0", tk.END)
    ciphertext_text.insert("1.0", final_encryption)

    messagebox.showinfo("Encryption", f"Product Cipher encryption successful!\nAverage Time taken: {encryption_time:.6f} seconds per iteration")

# Decrypt using Product Cipher 
def decrypt_with_product_cipher():
    """Decrypt using Columnar Transposition + Affine Cipher with precise timing."""
    ciphertext = ciphertext_text.get("1.0", "end-1c").strip()
    if not ciphertext:
        messagebox.showerror("Error", "Ciphertext is missing!")
        return

    iterations = 1000
    start_time = time.perf_counter()
    for _ in range(iterations):
        columnar_decrypted = columnar_transpose_decrypt(ciphertext)
        final_decryption = affine_decrypt(columnar_decrypted)
    decryption_time = (time.perf_counter() - start_time) / iterations
    decrypted_text_text.delete("1.0", tk.END)
    decrypted_text_text.insert("1.0", final_decryption)

    messagebox.showinfo("Decryption", f"Product Cipher decryption successful!\nAverage Time taken: {decryption_time:.6f} seconds per iteration")


# AES Key Generation
def self_generate_aes_key():
    """Generate a random 16-byte AES key and display it in Base64 format."""
    secret_key = os.urandom(16)
    aes_key_text.delete("1.0", tk.END)
    aes_key_text.insert("1.0", base64.b64encode(secret_key).decode())
    messagebox.showinfo("AES Key Generation", "AES key generated successfully!")

# AES Encryption/Decryption
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext + ' ' * (16 - len(plaintext) % 16)
    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext).decode().strip()

# RSA Key Generation
def generate_keys():
    """Generate RSA Key Pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_text.delete("1.0", tk.END)
    private_key_text.insert("1.0", private_pem.decode())

    public_key_text.delete("1.0", tk.END)
    public_key_text.insert("1.0", public_pem.decode())

    messagebox.showinfo("Key Generation", "Keys generated successfully!")

    # RSA Encryption of AES Key
def rsa_encrypt_key(aes_key, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode()

# RSA Decryption of AES Key
def rsa_decrypt_key(encrypted_key, private_key_pem):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Key Management Section Update
def exchange_secret_key():
    aes_key = os.urandom(16)
    aes_key_text.delete("1.0", tk.END)
    aes_key_text.insert("1.0", base64.b64encode(aes_key).decode())

    public_key_pem = public_key_text.get("1.0", "end-1c").strip()
    if not public_key_pem:
        messagebox.showerror("Error", "Public Key is missing!")
        return

    encrypted_key = rsa_encrypt_key(aes_key, public_key_pem)
    encrypted_key_text.delete("1.0", tk.END)
    encrypted_key_text.insert("1.0", encrypted_key)
    messagebox.showinfo("Key Exchange", "Secret Key successfully exchanged!")

def decrypt_secret_key():
    encrypted_key = encrypted_key_text.get("1.0", "end-1c").strip()
    private_key_pem = private_key_text.get("1.0", "end-1c").strip()
    if not encrypted_key or not private_key_pem:
        messagebox.showerror("Error", "Missing Private Key or Encrypted Key!")
        return

    try:
        decrypted_key = rsa_decrypt_key(encrypted_key, private_key_pem)
        decrypted_key_base64 = base64.b64encode(decrypted_key).decode()

        decrypted_key_text.delete("1.0", tk.END)
        decrypted_key_text.insert("1.0", decrypted_key_base64)

        messagebox.showinfo("Decryption", "Secret Key successfully decrypted!\n\nDecrypted AES Key:\n" + decrypted_key_base64)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed: " + str(e))

    decrypted_key = rsa_decrypt_key(encrypted_key, private_key_pem)
    aes_key_text.delete("1.0", tk.END)
    aes_key_text.insert("1.0", base64.b64encode(decrypted_key).decode())
    messagebox.showinfo("Decryption", "Secret Key successfully decrypted!")

def introduce_bit_error():
    """Introduce a single-bit error in the ciphertext."""
    ciphertext = ciphertext_text.get("1.0", "end-1c").strip()
    if not ciphertext:
        messagebox.showerror("Error", "Ciphertext is missing!")
        return

    ciphertext_bytes = bytearray(ciphertext.encode())  # Convert to byte array
    if not ciphertext_bytes:
        messagebox.showerror("Error", "Ciphertext encoding failed!")
        return

    random_byte_index = random.randint(0, len(ciphertext_bytes) - 1)
    random_bit_index = random.randint(0, 7)

    # Flip a single bit using XOR
    ciphertext_bytes[random_byte_index] ^= (1 << random_bit_index)

    corrupted_ciphertext = ciphertext_bytes.decode(errors='replace')  # Handle decoding errors

    log_text.insert(tk.END, f"Original Ciphertext:\n{ciphertext}\n")
    log_text.insert(tk.END, f"Corrupted Ciphertext:\n{corrupted_ciphertext}\n")
    log_text.insert(tk.END, "-" * 80 + "\n")

    ciphertext_text.delete("1.0", tk.END)
    ciphertext_text.insert("1.0", corrupted_ciphertext)

    messagebox.showinfo("Bit Error", "A single-bit error was introduced successfully!")


# GUI Layout
frame_key = tk.LabelFrame(root, text=" Key Management ", font=default_font, bg="#ffffff", padx=10, pady=10)
frame_key.pack(pady=10, fill="x", padx=15)

frame_encrypt = tk.LabelFrame(root, text=" Encryption and Decryption ", font=default_font, bg="#ffffff", padx=10, pady=10)
frame_encrypt.pack(pady=10, fill="x", padx=15)

frame_log = tk.LabelFrame(root, text=" Ciphertext Change Log ", font=default_font, bg="#ffffff", padx=10, pady=10)
frame_log.pack(pady=10, fill="both", expand=True, padx=15)

# Key Management Section
tk.Label(frame_key, text="Private Key:", font=default_font, bg="#ffffff").grid(row=0, column=0, sticky="w")
private_key_text = tk.Text(frame_key, height=5, width=60, font=("Courier New", 10))
private_key_text.grid(row=1, column=0, padx=5, pady=5)

tk.Label(frame_key, text="Public Key:", font=default_font, bg="#ffffff").grid(row=0, column=1, sticky="w")
public_key_text = tk.Text(frame_key, height=5, width=60, font=("Courier New", 10))
public_key_text.grid(row=1, column=1, padx=5, pady=5)

tk.Button(frame_key, text="Generate Keys", font=button_font, bg="#4CAF50", fg="white", command=generate_keys).grid(row=2, column=0, columnspan=2, pady=10, ipadx=10)

# Encryption and Decryption Section (Properly Aligned)
tk.Label(frame_encrypt, text="AES Key (Base64):", font=default_font, bg="#ffffff").grid(row=0, column=0, sticky="w")
aes_key_text = tk.Text(frame_encrypt, height=2, width=60, font=("Courier New", 10))
aes_key_text.grid(row=0, column=1, padx=10, pady=5)

tk.Label(frame_encrypt, text="Encrypted AES Key:", font=default_font, bg="#ffffff").grid(row=1, column=0, sticky="w")
encrypted_key_text = tk.Text(frame_encrypt, height=2, width=60, font=("Courier New", 10))
encrypted_key_text.grid(row=1, column=1, padx=10, pady=5)

tk.Label(frame_encrypt, text="Decrypted AES Key:", font=default_font, bg="#ffffff").grid(row=2, column=0, sticky="w")
decrypted_key_text = tk.Text(frame_encrypt, height=2, width=60, font=("Courier New", 10))
decrypted_key_text.grid(row=2, column=1, padx=10, pady=5)

exchange_button = tk.Button(frame_encrypt, text="Exchange Secret Key", bg="#007BFF", fg="white", command=exchange_secret_key)
exchange_button.grid(row=3, column=0, padx=5, pady=3, ipadx=10, sticky="w")

decrypt_button = tk.Button(frame_encrypt, text="Decrypt Secret Key", bg="#FF5722", fg="white", command=decrypt_secret_key)
decrypt_button.grid(row=3, column=1, padx=5, pady=3, ipadx=10, sticky="w")

tk.Label(frame_encrypt, text="Plaintext:", font=default_font, bg="#ffffff").grid(row=4, column=0, sticky="w")
plaintext_text = tk.Text(frame_encrypt, height=2, width=60, font=("Courier New", 10))
plaintext_text.grid(row=4, column=1, padx=10, pady=5)

tk.Label(frame_encrypt, text="Ciphertext:", font=default_font, bg="#ffffff").grid(row=5, column=0, sticky="w")
ciphertext_text = tk.Text(frame_encrypt, height=2, width=60, font=("Courier New", 10))
ciphertext_text.grid(row=5, column=1, padx=10, pady=5)

tk.Label(frame_encrypt, text="Decrypted Text:", font=default_font, bg="#ffffff").grid(row=6, column=0, sticky="w")
decrypted_text_text = tk.Text(frame_encrypt, height=2, width=60, font=("Courier New", 10))
decrypted_text_text.grid(row=6, column=1, padx=10, pady=5)

# Moved buttons below Decrypted Text (Aligned)
button_frame = tk.Frame(frame_encrypt, bg="#ffffff")
button_frame.grid(row=7, column=0, columnspan=2, pady=15)

tk.Button(button_frame, text="Encrypt with Product Cipher", font=button_font, bg="#673AB7", fg="white", width=25, command=encrypt_with_product_cipher).grid(row=0, column=0, padx=10, pady=5)
tk.Button(button_frame, text="Decrypt with Product Cipher", font=button_font, bg="#FF5722", fg="white", width=25, command=decrypt_with_product_cipher).grid(row=0, column=1, padx=10, pady=5)
tk.Button(button_frame, text="Introduce Bit Error", font=button_font, bg="#f44336", fg="white", width=25, command=introduce_bit_error).grid(row=0, column=2, padx=10, pady=5)


log_text = tk.Text(frame_log, height=10, font=("Courier New", 10), bg="#f5f5f5")
log_text.pack(fill="both", expand=True, padx=5, pady=5)

root.mainloop()

import os
import csv
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def get_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_filename(filename, fernet):
    return fernet.encrypt(filename.encode()).decode()

def decrypt_filename(encrypted_filename, fernet):
    return fernet.decrypt(encrypted_filename.encode()).decode()

def save_vault_files_to_csv(vault_directory, output_csv, password):
    key, salt = get_key_from_password(password)
    fernet = Fernet(key)
    
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Decrypted Filepath', 'Encrypted Filepath'])
        
        for root, _, files in os.walk(vault_directory):
            for file in files:
                decrypted_path = os.path.abspath(os.path.join(root, file))
                encrypted_filename = encrypt_filename(file, fernet)
                encrypted_path = os.path.join(os.path.dirname(decrypted_path), encrypted_filename)
                writer.writerow([decrypted_path, encrypted_path])

    # Save salt for later use
    with open(output_csv + '.salt', 'wb') as salt_file:
        salt_file.write(salt)

    print(f"File list saved to {output_csv}")
    print(f"Salt saved to {output_csv}.salt")

def read_and_decrypt_csv(input_csv, password):
    # Read salt
    with open(input_csv + '.salt', 'rb') as salt_file:
        salt = salt_file.read()

    key, _ = get_key_from_password(password, salt)
    fernet = Fernet(key)
    
    decrypted_files = []
    with open(input_csv, 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header
        for row in reader:
            decrypted_path, encrypted_path = row
            encrypted_filename = os.path.basename(encrypted_path)
            decrypted_filename = decrypt_filename(encrypted_filename, fernet)
            decrypted_files.append((decrypted_path, decrypted_filename))
    
    return decrypted_files

# Example usage
vault_directory = r't:/'
output_csv = 'vault_files.csv'
password = "klop.123"

# Save encrypted filenames to CSV
save_vault_files_to_csv(vault_directory, output_csv, password)

# Read and decrypt filenames from CSV
decrypted_files = read_and_decrypt_csv(output_csv, password)
for original_path, decrypted_filename in decrypted_files:
    print(f"Original: {original_path}")
    print(f"Decrypted filename: {decrypted_filename}")
    print()

import csv
import os
from cryptography.fernet import Fernet

def generate_or_load_key(key_file='encryption_key.key'):
    if os.path.exists(key_file):
        with open(key_file, 'rb') as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as file:
            file.write(key)
        return key

def encrypt_filename(filename, fernet):
    return fernet.encrypt(filename.encode()).decode()

def decrypt_filename(encrypted_filename, fernet):
    return fernet.decrypt(encrypted_filename.encode()).decode()

def save_vault_files_to_csv(vault_directory, output_csv, key_file='encryption_key.key'):
    key = generate_or_load_key(key_file)
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

    print(f"File list saved to {output_csv}")
    print(f"Encryption key saved to {key_file}")

def read_and_decrypt_csv(input_csv, key_file='encryption_key.key'):
    with open(key_file, 'rb') as file:
        key = file.read()
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
vault_directory = 'c:/3-A1'
output_csv = 'vault_files.csv'
key_file = 'klop.123.key'

# Save encrypted filenames to CSV
save_vault_files_to_csv(vault_directory, output_csv, key_file)

# Read and decrypt filenames from CSV
decrypted_files = read_and_decrypt_csv(output_csv, key_file)
for original_path, decrypted_filename in decrypted_files:
    print(f"Original: {original_path}")
    print(f"Decrypted filename: {decrypted_filename}")
    print()

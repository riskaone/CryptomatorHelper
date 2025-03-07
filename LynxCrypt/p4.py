import csv
import os
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_filepath(filepath, key):
    f = Fernet(key)
    return f.encrypt(filepath.encode()).decode()

def decrypt_filepath(encrypted_filepath, key):
    f = Fernet(key)
    return f.decrypt(encrypted_filepath.encode()).decode()

def save_vault_files_to_csv(vault_directory, output_csv):
    key = generate_key()
    
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Decrypted Filepath', 'Encrypted Filepath'])
        
        for root, _, files in os.walk(vault_directory):
            for file in files:
                decrypted_path = os.path.abspath(os.path.join(root, file))
                encrypted_path = os.path.join(os.path.dirname(decrypted_path), 
                                              encrypt_filepath(os.path.basename(decrypted_path), key))
                writer.writerow([decrypted_path, encrypted_path])

    print(f"File list saved to {output_csv}")
    print(f"Encryption key: {key.decode()}")

# Example usage
vault_directory = 't:/'
output_csv = 'vault_files.csv'
save_vault_files_to_csv(vault_directory, output_csv)

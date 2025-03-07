import os
import csv
from pycryptomator import Cryptomator

def browse_vault(vault_path, password, output_csv):
    # Initialize Cryptomator vault
    vault = Cryptomator(vault_path, password)
    
    # Open the vault
    vault.unlock()
    
    # List to store file information
    file_info = []
    
    # Recursive function to browse files
    def browse_directory(directory):
        for item in vault.ls(directory):
            encrypted_path = os.path.join(directory, item['name'])
            decrypted_path = vault.path(encrypted_path)
            
            if item['type'] == 'file':
                file_info.append({
                    'decrypted_filepath': decrypted_path,
                    'encrypted_filepath': encrypted_path
                })
            elif item['type'] == 'dir':
                browse_directory(encrypted_path)
    
    # Start browsing from the root
    browse_directory('/')
    
    # Save to CSV
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['decrypted_filepath', 'encrypted_filepath']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for item in file_info:
            writer.writerow(item)
    
    # Close the vault
    vault.lock()

# Example usage
vault_path = 'c:/3-A1'
password = 'klop.123'
output_csv = 'vault_files.csv'

browse_vault(vault_path, password, output_csv)
print(f"File information saved to {output_csv}")

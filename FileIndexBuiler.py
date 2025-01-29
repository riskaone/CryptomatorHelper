import os
import json
import hashlib
from pathlib import Path

def generate_vault_index(vault_path, onedrive_path, output_file):
    """
    Generate a mapping of original file paths to their encrypted counterparts in a Cryptomator vault on OneDrive.

    Args:
        vault_path (str): Path to the decrypted Cryptomator vault.
        onedrive_path (str): Path to the OneDrive folder containing the encrypted vault.
        output_file (str): Path to save the JSON index file.
    """
    file_index = {}

    vault_path = Path(vault_path)
    onedrive_path = Path(onedrive_path)

    # Walk through the decrypted vault
    for root, _, files in os.walk(vault_path):
        for file in files:
            print("File: ", file)
            original_path = Path(root) / file
            relative_path = original_path.relative_to(vault_path)

            # Generate a hash of the original file path to simulate Cryptomator's encryption
            encrypted_name = hashlib.sha256(str(relative_path).encode()).hexdigest()[:32]
            print("encrypted_name: ", encrypted_name)

            # Find the corresponding encrypted file in OneDrive
            for encrypted_file in onedrive_path.rglob(f"*{encrypted_name}*"):
                print("encrypted_file: ", encrypted_file)
                if encrypted_file.suffix == ".c9r":  # Cryptomator's encrypted file extension
                    encrypted_path = encrypted_file.relative_to(onedrive_path)
                    file_index[str(relative_path)] = str(encrypted_path)
                    
                    break
        print("---------------------------------------------------\n")

    # Save the index to a JSON file
    with open(output_file, 'w') as f:
        json.dump(file_index, f, indent=4)

    print(f"Index saved to {output_file}")

# Example usage
vault_path = "c:/__INDEXTEST"
onedrive_path = "o:/TIGERNET/OneDrive/_IndexTEST/IndexTEST"
output_file = "vault_index.json"

generate_vault_index(vault_path, onedrive_path, output_file)

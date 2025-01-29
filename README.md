# BoxcryptorHelper

### It doesn't work as scrypt can't find and encrypted filename

# Example usage
vault_path = "C:/Users/YourUsername/Cryptomator/DecryptedVault"
onedrive_path = "C:/Users/YourUsername/OneDrive/CryptomatorVault"
output_file = "vault_index.json"

generate_vault_index(vault_path, onedrive_path, output_file)


This script does the following:

1. It walks through the decrypted Cryptomator vault and generates a hash for each file path to simulate Cryptomator's encryption.

2. For each file in the decrypted vault, it searches for a corresponding encrypted file in the OneDrive folder.

3. When a match is found, it adds the mapping of the original file path to the encrypted file path to the index.

4. Finally, it saves the index as a JSON file.

To use this script:

1. Replace `vault_path` with the path to your decrypted Cryptomator vault.
2. Replace `onedrive_path` with the path to the OneDrive folder containing your encrypted Cryptomator vault.
3. Set `output_file` to the desired location for the JSON index file.

Run the script when your vault is unlocked to generate the index. This index will allow you to look up the encrypted filepath and name for any file in your vault.

Note that this script assumes Cryptomator's default encryption behavior. The actual encryption method may be more complex, so this is an approximation. Always keep your vault locked when not in use to maintain security[2][4].

Citations:
[1] https://www.youtube.com/watch?v=kuVOyiqJduQ
[2] https://github.com/cryptomator/cryptomator/issues/1579
[3] https://community.cryptomator.org/t/python-script-to-reveal-an-unlocked-file-for-encrypted-files-in-a-vault-and-vice-versa/9765
[4] https://dev.to/andreagrandi/cryptomator-end-to-end-encrypt-files-in-any-cloud-54kc
[5] https://community.cryptomator.org/t/how-can-i-tell-which-encrypted-file-corresponds-to-which-original-file/10077
[6] https://stackoverflow.com/questions/55836052/tag-mismatch-when-trying-to-decrypt-encrypted-data
[7] https://www.reddit.com/r/Cryptomator/comments/19apvy9/does_cryptomator_encrypt_through_cloud_only_or/
[8] https://discourse.omnigroup.com/t/omnifocus-sync-encryption-gory-technical-details/24611
[9] https://www.reddit.com/r/privacy/comments/1d2yqee/how_do_i_encrypt_my_files_before_uploading_them/
[10] https://informationssicherheit.uni-wuppertal.de/fileadmin/informationssicherheit/How_to_encrypt_with_Cryptomator.pdf
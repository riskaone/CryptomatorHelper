import os
import csv
import datetime
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(filename='vault_file_list.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_file_info(filepath):
    """Get file size and last modified date"""
    try:
        stat = os.stat(filepath)
        size = stat.st_size
        modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        return size, modified
    except OSError as e:
        logging.error(f"Error getting file info for {filepath}: {e}")
        return None, None

def save_unlocked_vault_files_to_csv(unlocked_vault_path, output_csv):
    unlocked_vault_path = Path(unlocked_vault_path)
    if not unlocked_vault_path.is_dir():
        logging.error(f"The specified path is not a directory: {unlocked_vault_path}")
        print(f"Error: The specified path is not a directory: {unlocked_vault_path}")
        return

    try:
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Filepath', 'Size (bytes)', 'Last Modified'])

            for root, dirs, files in os.walk(unlocked_vault_path):
                for file in files:
                    filepath = Path(root) / file
                    size, modified = get_file_info(filepath)
                    if size is not None and modified is not None:
                        writer.writerow([str(filepath), size, modified])
                    else:
                        logging.warning(f"Skipped file due to error: {filepath}")

        print(f"CSV file created successfully: {output_csv}")
        logging.info(f"CSV file created successfully: {output_csv}")
    except IOError as e:
        logging.error(f"Error writing to CSV file: {e}")
        print(f"Error: Unable to write to CSV file: {e}")

def main():
    #  = input("Enter the path to your unlocked Cryptomator vault: ")
    unlocked_vault_path = "T:/"
    # output_csv = input("Enter the name of the output CSV file (e.g., vault_files.csv): ")
    output_csv = 'vault_files.csv'

    save_unlocked_vault_files_to_csv(unlocked_vault_path, output_csv)

if __name__ == "__main__":
    main()

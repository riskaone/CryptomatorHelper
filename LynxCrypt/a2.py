import os
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
import win32api

# Configuration (Update these paths based on your setup)
VAULT_MOUNT_POINT = "T:\\"  # The virtual drive where the Cryptomator vault is mounted
VAULT_ENCRYPTED_ROOT = "c:\3-A1"  # Path to the encrypted vault folder

class EncryptedFileBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted File Browser")
        self.root.geometry("800x400")

        # Treeview to display files
        self.tree = ttk.Treeview(self.root, columns=("Name", "Decrypted Path", "Encrypted Path"), show="headings")
        self.tree.heading("Name", text="File Name")
        self.tree.heading("Decrypted Path", text="Decrypted Path")
        self.tree.heading("Encrypted Path", text="Encrypted Path")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Populate the tree with files from the vault
        self.load_files(VAULT_MOUNT_POINT)

        # Bind right-click event
        self.tree.bind("<Button-3>", self.on_right_click)

    def load_files(self, directory):
        """Recursively load files from the mounted vault and find encrypted paths."""
        try:
            for item in os.listdir(directory):
                decrypted_path = os.path.join(directory, item)
                if os.path.isfile(decrypted_path):
                    # Try to find the corresponding encrypted file
                    encrypted_path = self.find_encrypted_path(decrypted_path)
                    self.tree.insert("", "end", values=(item, decrypted_path, encrypted_path or "Not Found"))
                elif os.path.isdir(decrypted_path):
                    self.load_files(decrypted_path)  # Recursive call for subdirectories
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load files: {e}")

    def find_encrypted_path(self, decrypted_path):
        """Find the encrypted path corresponding to a decrypted file."""
        try:
            # Get relative path from mount point
            relative_path = Path(decrypted_path).relative_to(VAULT_MOUNT_POINT)
            # Simplify: Assume encrypted structure mirrors decrypted (not true for filenames)
            # In reality, we need directory IDs and master key to decode filenames
            encrypted_base = Path(VAULT_ENCRYPTED_ROOT) / "d"

            # Walk the encrypted vault to find a match (using file size as a heuristic)
            decrypted_size = os.path.getsize(decrypted_path)
            for root, _, files in os.walk(encrypted_base):
                for enc_file in files:
                    enc_path = Path(root) / enc_file
                    if enc_path.suffix != ".c9r":  # Skip directory metadata files
                        if os.path.getsize(enc_path) == decrypted_size:
                            # Potential match (not guaranteed without decryption)
                            return str(enc_path)
            return None  # No match found
        except Exception as e:
            return f"Error: {e}"

    def on_right_click(self, event):
        """Handle right-click event and show context menu."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            selected_file = self.tree.item(item, "values")[1]  # Get decrypted path

            # Create context menu
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Open in Windows Explorer (Encrypted)", 
                           command=lambda: self.open_in_explorer(selected_file))
            menu.post(event.x_root, event.y_root)

    def open_in_explorer(self, decrypted_path):
        """Open the encrypted file's folder in Windows Explorer."""
        encrypted_path = self.find_encrypted_path(decrypted_path)
        if encrypted_path and "Error" not in encrypted_path:
            encrypted_dir = Path(encrypted_path).parent
            win32api.ShellExecute(0, "open", "explorer.exe", f"\"{encrypted_dir}\"", None, 1)
        else:
            messagebox.showwarning("Warning", f"Could not locate encrypted file for: {decrypted_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedFileBrowser(root)
    root.mainloop()
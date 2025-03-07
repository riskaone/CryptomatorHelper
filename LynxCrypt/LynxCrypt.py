import os
import tkinter as tk
from tkinter import ttk, messagebox
import win32gui
import win32con
import win32api
from pathlib import Path

# Configuration (Update these paths based on your setup)
VAULT_MOUNT_POINT = "T:\\"  # The virtual drive where the Cryptomator vault is mounted
VAULT_ENCRYPTED_ROOT = "c:\3-A1"  # Path to the encrypted vault folder

class EncryptedFileBrowser:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted File Browser")
        self.root.geometry("600x400")

        # Treeview to display files
        self.tree = ttk.Treeview(self.root, columns=("Name", "Path"), show="headings")
        self.tree.heading("Name", text="File Name")
        self.tree.heading("Path", text="Decrypted Path")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Populate the tree with files from the vault
        self.load_files(VAULT_MOUNT_POINT)

        # Bind right-click event
        self.tree.bind("<Button-3>", self.on_right_click)

    def load_files(self, directory):
        """Recursively load files from the mounted vault."""
        try:
            for item in os.listdir(directory):
                full_path = os.path.join(directory, item)
                if os.path.isfile(full_path):
                    self.tree.insert("", "end", values=(item, full_path))
                elif os.path.isdir(full_path):
                    self.load_files(full_path)  # Recursive call for subdirectories
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load files: {e}")

    def on_right_click(self, event):
        """Handle right-click event and show context menu."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            selected_file = self.tree.item(item, "values")[1]  # Get decrypted path

            # Create context menu
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Open in Windows Explorer", 
                           command=lambda: self.open_in_explorer(selected_file))
            menu.post(event.x_root, event.y_root)

    def open_in_explorer(self, decrypted_path):
        """Open the encrypted file's folder in Windows Explorer."""
        try:
            # Convert decrypted path to encrypted path
            relative_path = Path(decrypted_path).relative_to(VAULT_MOUNT_POINT)
            encrypted_path = Path(VAULT_ENCRYPTED_ROOT) / "d" / self.get_encrypted_path(relative_path)

            # Ensure the directory exists
            encrypted_dir = encrypted_path.parent

            print(encrypted_dir)

            if encrypted_dir.exists():
                # Open Windows Explorer to the encrypted folder
                win32api.ShellExecute(0, "open", "explorer.exe", f"/select,\"{encrypted_path}\"", None, 1)
            else:
                messagebox.showerror("Error", "Encrypted folder not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Explorer: {e}")

    def get_encrypted_path(self, relative_path):
        """Convert a relative decrypted path to its encrypted equivalent."""
        # This is a simplified version; Cryptomator uses a complex naming scheme
        # In a real implementation, you'd need to reverse-engineer or use Cryptomator's API
        # For demo purposes, assume a simple mapping (not accurate for real Cryptomator vaults)
        return relative_path  # Placeholder; actual encryption mapping needed

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedFileBrowser(root)
    root.mainloop()
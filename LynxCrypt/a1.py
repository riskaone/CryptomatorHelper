import os
import tkinter as tk
from tkinter import ttk, messagebox
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
            menu.add_command(label="Open in Windows Explorer (Encrypted)", 
                           command=lambda: self.open_in_explorer(selected_file))
            menu.post(event.x_root, event.y_root)

    def open_in_explorer(self, decrypted_path):
        """Open the encrypted file's folder in Windows Explorer."""
        try:
            # Convert decrypted path to a relative path from the mount point
            relative_path = Path(decrypted_path).relative_to(VAULT_MOUNT_POINT)
            
            # Construct the encrypted folder path (simplified)
            # Note: This assumes the encrypted folder structure mirrors the decrypted one under 'd'
            # In reality, Cryptomator encrypts file names, so this is a simplification
            encrypted_dir = Path(VAULT_ENCRYPTED_ROOT) / "d" / relative_path.parent

            if encrypted_dir.exists():
                # Open Windows Explorer to the encrypted folder
                win32api.ShellExecute(0, "open", "explorer.exe", f"\"{encrypted_dir}\"", None, 1)
            else:
                # If the exact folder isn't found, open the vault root and warn the user
                vault_root = Path(VAULT_ENCRYPTED_ROOT)
                win32api.ShellExecute(0, "open", "explorer.exe", f"\"{vault_root}\"", None, 1)
                messagebox.showwarning("Warning", 
                    f"Could not locate exact encrypted folder: {encrypted_dir}\nOpening vault root instead.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Explorer: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedFileBrowser(root)
    root.mainloop()
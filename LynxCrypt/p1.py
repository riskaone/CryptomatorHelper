import tkinter as tk
from tkinter import ttk
import pycryptomator
import os
import subprocess

class EncryptedFileBrowser(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Encrypted File Browser")
        self.geometry("600x400")

        # Initialize pycryptomator vault
        self.vault = pycryptomator.Vault('c:/3-A1')
        print(45)
        self.vault.unlock("klop.123")

        print(self.vault)

        # Create treeview
        self.tree = ttk.Treeview(self)
        self.tree.pack(expand=True, fill='both')

        # Add columns
        self.tree["columns"] = ("size", "date_modified")
        self.tree.column("#0", width=200, minwidth=200)
        self.tree.column("size", width=100, minwidth=100)
        self.tree.column("date_modified", width=150, minwidth=150)

        self.tree.heading("#0", text="Name", anchor=tk.W)
        self.tree.heading("size", text="Size", anchor=tk.W)
        self.tree.heading("date_modified", text="Date Modified", anchor=tk.W)

        # Populate the treeview
        self.populate_tree()

        # Bind right-click event
        self.tree.bind("<Button-3>", self.show_context_menu)

    def populate_tree(self, parent=''):
        for item in self.vault.listdir(parent):
            full_path = os.path.join(parent, item)
            item_type = self.vault.getinfo(full_path).type
            size = self.vault.getinfo(full_path).size
            date_modified = self.vault.getinfo(full_path).mtime

            item_id = self.tree.insert(parent, 'end', text=item, values=(size, date_modified))

            if item_type == 'dir':
                self.populate_tree(full_path)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Open Folder", command=self.open_folder)
            menu.post(event.x_root, event.y_root)

    def open_folder(self):
        selected_item = self.tree.selection()[0]
        item_path = self.get_item_path(selected_item)
        real_path = self.vault.get_real_path(item_path)
        folder_path = os.path.dirname(real_path)
        subprocess.Popen(f'explorer "{folder_path}"')

    def get_item_path(self, item):
        path = self.tree.item(item, "text")
        parent = self.tree.parent(item)
        while parent:
            path = os.path.join(self.tree.item(parent, "text"), path)
            parent = self.tree.parent(parent)
        return path

if __name__ == "__main__":
    app = EncryptedFileBrowser()
    app.mainloop()

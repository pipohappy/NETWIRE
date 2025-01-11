import json
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Global variable to keep track of scan history
scan_history = []

def save_scan(device_tree):
    """Save the current scan to a JSON file and add it to the history."""
    global scan_history

    # Get all items from the Treeview
    device_data = []
    for child in device_tree.get_children():
        device_data.append(device_tree.item(child)["values"])

    # Add a timestamp to the saved data
    scan_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "devices": device_data
    }

    # Prompt the user to save the file
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
    
    if file_path:
        with open(file_path, "w") as f:
            json.dump(scan_data, f)
        # Add to scan history
        scan_history.append({"timestamp": scan_data["timestamp"], "file_path": file_path})
        messagebox.showinfo("Save Scan", f"Scan saved to {file_path}")
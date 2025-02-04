import paramiko 
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import chardet
import time

class Console:
    def __init__(self, main_frame, stop_scanning):
        self.main_frame = main_frame
        self.stop_scanning = stop_scanning
        self.protocol = tk.StringVar(value="ssh")
        self.address = tk.StringVar()
        self.port = tk.StringVar(value="22")
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.ssh_client = None
        self.shell = None
        self.command_history = []
        self.history_index = 0

        self.top_frame = ttk.Frame(self.main_frame, style="Main.TFrame")
        self.top_frame.pack(side="top", fill="x", padx=10, pady=10)

        ttk.Label(self.top_frame, text="Protocol:", style="Console.TLabel").pack(side="left", padx=(0, 5))
        protocol_menu = ttk.OptionMenu(self.top_frame, self.protocol, "SSH", "SSH")
        protocol_menu.pack(side="left")

        ttk.Label(self.top_frame, text="Address:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.address).pack(side="left", padx=(0, 5))

        ttk.Label(self.top_frame, text="Port:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.port, width=5).pack(side="left", padx=(0, 5))
        
        ttk.Label(self.top_frame, text="Username:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.username).pack(side="left", padx=(0, 5))

        ttk.Label(self.top_frame, text="Password:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.password, show="*").pack(side="left", padx=(0, 5))

        ttk.Button(self.top_frame, text="Connect", style="Console.TButton", command=self.connect).pack(side="left", padx=5)
        ttk.Button(self.top_frame, text="Disconnect", style="Console.TButton", command=self.disconnect).pack(side="left", padx=5)

        self.output_text = scrolledtext.ScrolledText(
            self.main_frame,
            wrap=tk.WORD,
            bg="#1e1e1e",
            fg="white",
            font=("Courier", 12),
            state="normal",
        )
        self.output_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.command_input = ttk.Entry(self.main_frame, width=60, font=("Courier", 12))
        self.command_input.pack(fill="x", padx=10, pady=10)
        self.command_input.bind("<Return>", self.handle_input)
        self.command_input.bind("<Up>", self.show_previous_command)
        self.command_input.bind("<Down>", self.show_next_command)

    def connect(self):
        address = self.address.get()
        port = int(self.port.get())
        username = self.username.get()
        password = self.password.get()
        
        self.append_output(f"Connecting to {address} via SSH...")
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(address, port=port, username=username, password=password, look_for_keys=False, allow_agent=False)
            self.shell = self.ssh_client.invoke_shell()
            self.append_output("SSH connection established. Running interactive CMD...")
            self.shell.send("chcp 65001\r\n")  # Set UTF-8 encoding in Windows CMD
            self.shell.send("cmd\r\n")  # Start Windows CMD session
            threading.Thread(target=self.read_shell_output, daemon=True).start()
        except Exception as e:
            self.append_output(f"SSH connection failed: {e}")

    def disconnect(self):
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            self.shell = None
        self.append_output("Disconnected.")

    def read_shell_output(self):
        while self.shell:
            try:
                time.sleep(0.1)  # Small delay to prevent excessive CPU usage
                if self.shell.recv_ready():
                    raw_output = self.shell.recv(4096)
                    encoding = "utf-8"  # Force UTF-8 encoding
                    output = raw_output.decode(encoding, errors='replace')
                    self.append_output(output)
            except Exception as e:
                self.append_output(f"Shell error: {e}")
                break

    def handle_input(self, event):
        command = self.command_input.get().strip()
        if command and self.shell:
            if command.lower() == "clear":
                # Clear the output text box when the "clear" command is entered
                self.clear_output()
            else:
                # Send the command to the shell for processing
                self.shell.send(command + "\r\n")
                # Save command to history
                self.command_history.append(command)
                self.history_index = len(self.command_history)  # Reset the history index after a new command
            self.command_input.delete(0, tk.END)
        return "break"
    
    def clear_output(self):
        # Clears the output_text widget
        self.output_text.config(state="normal")  # Enable editing to delete content
        self.output_text.delete(1.0, tk.END)  # Delete all text from the start to the end
        self.output_text.config(state="disabled")  # Disable editing again

    def show_previous_command(self, event):
        # Navigate to the previous command in history
        if self.history_index > 0:
            self.history_index -= 1
            self.command_input.delete(0, tk.END)
            self.command_input.insert(0, self.command_history[self.history_index])
        return "break"

    def show_next_command(self, event):
        # Navigate to the next command in history
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_input.delete(0, tk.END)
            self.command_input.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            # If we're at the last command, clear the input field
            self.command_input.delete(0, tk.END)
        return "break"

    def append_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.insert("end", text)
        self.output_text.insert("end", "\n")
        self.output_text.config(state="disabled")
        self.output_text.yview("end")

def navigate_to_console(main_frame, stop_scanning):
    for widget in main_frame.winfo_children():
        widget.destroy()
    console = Console(main_frame, stop_scanning)
    return console

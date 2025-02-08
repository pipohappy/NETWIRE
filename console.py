import paramiko
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, Button
from PIL import Image, ImageTk
from guidance_console import guidance_of_console
import os
import sys
import time

class Console:
    def __init__(self, main_frame):
        self.main_frame = main_frame
        self.protocol = tk.StringVar(value="ssh")  # Default to SSH
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
        protocol_menu = ttk.OptionMenu(self.top_frame, self.protocol, "SSH", "SSH", "Telnet")
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

        def resource_path(relative_path):
            """ Get the absolute path to a resource bundled with PyInstaller """
            try:
                base_path = sys._MEIPASS
            except Exception:
                base_path = os.path.abspath(".")
            return os.path.join(base_path, relative_path)

        guidance_image = Image.open(resource_path("assets/guidance.png"))  # Replace with your image path
        guidance_image = guidance_image.resize((40, 40))
        guidance_icon = ImageTk.PhotoImage(guidance_image)

        new_button = Button(
        self.top_frame,
        image=guidance_icon,
        bd=1,
        bg="#2c2c2c",
        highlightthickness=0,
        activebackground='#181818'
        )

        # Set the command separately
        new_button.config(command=guidance_of_console)
        
        new_button.image = guidance_icon  # Keep a reference to avoid garbage collection
        new_button.pack(side="right", padx=(5, 0))

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
        
        # Bind Ctrl+C to handle the interrupt
        self.command_input.bind("<Control-c>", self.handle_ctrl_c)

    def connect(self):
        address = self.address.get()
        port = int(self.port.get())
        username = self.username.get()
        password = self.password.get()

        if self.protocol.get() == "SSH":
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
        elif self.protocol.get() == "Telnet":
            self.append_output(f"Connecting to {address} via Telnet...")
            try:
                import telnetlib
                self.telnet_client = telnetlib.Telnet(address, port)
                self.append_output("Telnet connection established.")
                threading.Thread(target=self.read_telnet_output, daemon=True).start()
            except Exception as e:
                self.append_output(f"Telnet connection failed: {e}")

    def disconnect(self):
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            self.shell = None
        elif hasattr(self, 'telnet_client') and self.telnet_client:
            self.telnet_client.close()
            self.telnet_client = None
        self.append_output("Disconnected.")

    def read_telnet_output(self):
        while hasattr(self, 'telnet_client') and self.telnet_client:
            try:
                time.sleep(0.1)  # Small delay to prevent excessive CPU usage
                output = self.telnet_client.read_very_eager().decode('utf-8', errors='replace')
                if output:
                    self.append_output(output)
            except Exception as e:
                if hasattr(self, 'telnet_client') and self.telnet_client:
                    self.append_output(f"Telnet error: {e}")
                break

    def read_shell_output(self):
        while self.shell:
            try:
                time.sleep(0.1)  # Small delay to prevent excessive CPU usage
                output = self.shell.recv(1024).decode('utf-8', errors='replace')
                if output:
                    self.append_output(output)
            except Exception as e:
                if self.shell:
                    self.append_output(f"SSH error: {e}")
                break

    def handle_input(self, event):
        command = self.command_input.get().strip()
        if command:
            if command.lower() == "clear":
                self.clear_output()
            elif self.shell:
                self.shell.send(command + "\r\n")
                self.command_history.append(command)
                self.history_index = len(self.command_history)
            elif hasattr(self, 'telnet_client') and self.telnet_client:
                self.telnet_client.write(command.encode('ascii') + b"\r\n")
                self.command_history.append(command)
                self.history_index = len(self.command_history)
            else:
                self.command_history.append(command)
                self.history_index = len(self.command_history)
            self.command_input.delete(0, tk.END)
        else:
            if self.shell:
                self.shell.send("\r\n")
            elif hasattr(self, 'telnet_client') and self.telnet_client:
                self.telnet_client.write(b"\r\n")
            self.command_input.delete(0, tk.END)
        return "break"

    def handle_ctrl_c(self, event):
        if self.shell:
            try:
                self.shell.send("\x03")  # Send the Ctrl+C signal (ASCII value 3)
                self.append_output("Interrupt signal (Ctrl+C) sent to the remote shell.")
            except Exception as e:
                self.append_output(f"Failed to send Ctrl+C: {e}")
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

def navigate_to_console(main_frame):
    for widget in main_frame.winfo_children():
        widget.destroy()
    console = Console(main_frame)
    return console

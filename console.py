import paramiko
import telnetlib
import threading
import time
import serial
import tkinter as tk
from tkinter import ttk, scrolledtext

class RemoteConsole:
    def __init__(self, main_frame, stop_scanning):
        self.main_frame = main_frame
        self.stop_scanning = stop_scanning  # Accept stop_scanning as an argument
        self.protocol = tk.StringVar(value="ssh")  # Default protocol
        self.address = tk.StringVar()
        self.port = tk.StringVar(value="22")  # Default SSH port
        self.baud_rate = tk.StringVar(value="9600")  # Default baud rate for serial

        self.client = None  # SSH client
        self.telnet = None  # Telnet client
        self.serial_conn = None  # Serial connection
        self.shell = None   # Interactive shell for SSH
        self.password_attempted = False  # Flag to prevent multiple password attempts

        # Initialize command history and history index
        self.command_history = []  # List to store command history
        self.history_index = 0  # Index to track current position in history

        self.setup_ui()

    def setup_ui(self):
        """Set up the UI for the Remote Console."""
        # Top Frame: Connection Settings
        self.top_frame = ttk.Frame(self.main_frame, style="Main.TFrame")
        self.top_frame.pack(side="top", fill="x", padx=10, pady=10)

        # Connection Settings
        ttk.Label(self.top_frame, text="Protocol:", foreground="orange", font=("Arial", 12)).pack(side="left", padx=(0, 5))
        protocol_menu = ttk.OptionMenu(self.top_frame, self.protocol, "SSH", "SSH", "Telnet", "Serial")  # Added Serial
        protocol_menu.pack(side="left")

        ttk.Label(self.top_frame, text="Address:", foreground="orange", font=("Arial", 12)).pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.address).pack(side="left", padx=(0, 5))

        ttk.Label(self.top_frame, text="Port (TCP/Serial):", foreground="orange", font=("Arial", 12)).pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.port, width=5).pack(side="left", padx=(0, 5))

        ttk.Label(self.top_frame, text="Baud Rate:", foreground="orange", font=("Arial", 12)).pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.baud_rate, width=8).pack(side="left", padx=5)

        ttk.Button(self.top_frame, text="Connect", style="Sidebar.TButton", command=self.connect).pack(side="left", padx=5)
        ttk.Button(self.top_frame, text="Disconnect", style="Sidebar.TButton", command=self.disconnect).pack(side="left", padx=5)

        # Main Terminal Window for output
        self.output_text = scrolledtext.ScrolledText(
            self.main_frame,
            wrap=tk.WORD,
            bg="#1e1e1e",  # Dark background for terminal
            fg="white",    # White text
            font=("Courier", 10),  # Monospaced font
            state="normal",        # Allow typing
        )
        self.output_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.command_input = ttk.Entry(self.main_frame, width=60, font=("Courier", 12))
        self.command_input.pack(fill="x", padx=10, pady=10)
        self.command_input.bind("<Return>", self.handle_input)  # Send command on Enter
        self.command_input.bind("<Up>", self.navigate_history_up)  # Bind up arrow key
        self.command_input.bind("<Down>", self.navigate_history_down)  # Bind down arrow key

    def connect(self):
        """Handle connection logic."""
        protocol = self.protocol.get().lower()
        address = self.address.get()
        port = self.port.get()

        if protocol == "serial":
            threading.Thread(target=self.start_serial_connection, args=(address, port), daemon=True).start()
        elif protocol == "ssh":
            threading.Thread(target=self.start_ssh_connection, args=(address, int(port)), daemon=True).start()
        elif protocol == "telnet":
            threading.Thread(target=self.start_telnet_connection, args=(address, int(port)), daemon=True).start()
        else:
            self.append_output("Unsupported protocol.")

    def disconnect(self):
        """Handle disconnection."""
        if self.client:
            self.client.close()
            self.client = None
        if self.telnet:
            self.telnet.close()
            self.telnet = None
        if self.serial_conn:
            self.serial_conn.close()
            self.serial_conn = None
        self.shell = None
        self.password_attempted = False  # Reset the flag
        self.append_output("Disconnected.")

    def start_ssh_connection(self, address, port):
        """Start an SSH connection with an interactive shell."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.append_output(f"Connecting to {address} via SSH...")
            self.client.connect(address, port=port, username=None, password=None)
            self.append_output("SSH connection established.")
            self.shell = self.client.invoke_shell()
            self.password_attempted = False  # Reset the flag for each connection
            threading.Thread(target=self.read_ssh_output, daemon=True).start()
        except Exception as e:
            self.append_output(f"SSH connection failed: {e}")

    def read_ssh_output(self):
        """Continuously read from the SSH shell and append to output."""
        buffer = ""
        while self.shell:
            try:
                data = self.shell.recv(1024).decode("utf-8")
                if data:
                    buffer += data
                    self.append_output(data)

                    # Handle username and password prompts dynamically
                    if "username:" in buffer.lower() and not self.password_attempted:
                        self.shell.send(self.command_input.get() + "\n")  # User enters username in the console
                        buffer = ""  # Clear buffer after processing
                    elif "password:" in buffer.lower() and not self.password_attempted:
                        self.shell.send(self.command_input.get() + "\n")  # User enters password in the console
                        self.password_attempted = True
                        buffer = ""  # Clear buffer after processing
            except Exception as e:
                self.append_output(f"SSH read error: {e}")
                break

    def start_telnet_connection(self, address, port):
        """Start a Telnet connection."""
        try:
            self.telnet = telnetlib.Telnet(address, port, timeout=10)
            self.append_output(f"Connecting to {address} via Telnet...")
            
            # Start a thread to read from the Telnet session
            threading.Thread(target=self.read_telnet_output, daemon=True).start()

        except Exception as e:
            self.append_output(f"Telnet connection failed: {e}")

    def read_telnet_output(self):
        """Continuously read from Telnet and append output."""
        buffer = ""
        try:
            while self.telnet:
                data = self.telnet.read_very_eager().decode("ascii")
                if data:
                    buffer += data
                    self.append_output(data)

                    # Handle username and password prompts dynamically
                    if "username:" in buffer.lower():
                        self.append_output("Username prompt detected. Please type your username and press Enter.")
                        buffer = ""  # Clear buffer after processing
                    elif "password:" in buffer.lower():
                        self.append_output("Password prompt detected. Please type your password and press Enter.")
                        buffer = ""  # Clear buffer after processing
        except Exception as e:
            self.append_output(f"Telnet read error: {e}")

    def handle_input(self, event):
        """Handle user input from the terminal."""
        command = self.command_input.get().strip()  # Get the command from the input field

        if command.lower() == "clear":
            # Clear the console output
            self.output_text.config(state="normal")
            self.output_text.delete(1.0, tk.END)  # Delete all content in the output
            self.output_text.config(state="disabled")
            self.command_input.delete(0, tk.END)  # Clear the command input
            return "break"

        if command:  # If the input has a command
            self.append_output(f"> {command}")  # Show the command in the terminal
            protocol = self.protocol.get().lower()
            if protocol == "serial":
                self.send_serial_command(command)
            elif protocol == "ssh" or protocol == "telnet":
                self.send_command(command)
            # Add command to history
            self.command_history.append(command)
            self.history_index = len(self.command_history)  # Reset history index to the latest position
            # Clear the input field after the command is processed
            self.command_input.delete(0, tk.END)
        else:  # If the input is empty (just "Enter" pressed)
            # Send only the Enter key (new line) to the router
            self.send_enter_key()  # Send just the "Enter" (newline) to the router

        # Ensure the terminal output stays scrolled to the bottom
        self.output_text.yview("end")  # Scroll to the end of the output

        return "break"  # Prevent default newline behavior

    def navigate_history_up(self, event):
        """Navigate the command history upwards."""
        if self.history_index > 0:
            self.history_index -= 1
            self.command_input.delete(0, tk.END)  # Clear the input
            self.command_input.insert(0, self.command_history[self.history_index])  # Insert previous command

    def navigate_history_down(self, event):
        """Navigate the command history downwards."""
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_input.delete(0, tk.END)  # Clear the input
            self.command_input.insert(0, self.command_history[self.history_index])  # Insert next command
        elif self.history_index == len(self.command_history) - 1:
            # After reaching the latest command in the history, clear the input field
            self.history_index += 1
            self.command_input.delete(0, tk.END)  # Clear the input field


    def send_enter_key(self):
        """Send only the 'Enter' key (newline) to the connected device (router)."""
        protocol = self.protocol.get().lower()
        
        if protocol == "serial" and self.serial_conn:
            self.serial_conn.write(b"\n")  # Send Enter as newline to serial device
        elif protocol == "ssh" and self.shell:
            self.shell.send(b"\n")  # Send Enter as newline to SSH session
        elif protocol == "telnet" and self.telnet:
            try:
                self.telnet.sock.send(b'')  # Verify the socket is still connected
                self.telnet.write(b"\n")  # Send Enter as newline to Telnet session
            except Exception as e:
                self.append_output(f"Telnet connection error: {e}")
                self.telnet = None  # Reset Telnet connection

    def send_command(self, command):
        """Send a command to the connected device."""
        if self.shell:
            self.shell.send(command + "\n")
        elif self.telnet:
            self.telnet.write(command.encode("ascii") + b"\n")

    def stop_scanning_when_leaving(self):
        """Stops scanning when navigating away from the console window."""
        self.stop_scanning()

    def append_output(self, text):
        """Helper function to append text to the terminal window."""
        self.output_text.config(state="normal")
        self.output_text.insert("end", text + "\n")
        self.output_text.config(state="disabled")
        self.output_text.yview("end")  # Scroll to the end

def navigate_to_console(main_frame, stop_scanning):
    """Function to navigate to the console interface."""
    for widget in main_frame.winfo_children():
        widget.destroy()
    RemoteConsole(main_frame, stop_scanning)
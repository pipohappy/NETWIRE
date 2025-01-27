import paramiko
import telnetlib
import threading
import time
import serial
import os
import sys
from PIL import Image, ImageTk
import tkinter as tk
from tkinter import ttk, scrolledtext, Button

class Console:
    def __init__(self, main_frame, stop_scanning):
        self.main_frame = main_frame
        self.stop_scanning = stop_scanning
        self.protocol = tk.StringVar(value="ssh")
        self.address = tk.StringVar()
        self.port = tk.StringVar(value="22")
        self.baud_rate = tk.StringVar(value="9600")
        self.com_port = tk.StringVar(value="COM1")
        self.client = None
        self.telnet = None
        self.serial_conn = None
        self.shell = None
        self.password_attempted = False
        self.max_command_history = 50
        self.command_history = []
        self.history_index = 0

        self.top_frame = ttk.Frame(self.main_frame, style="Main.TFrame")
        self.top_frame.pack(side="top", fill="x", padx=10, pady=10)

        ttk.Label(self.top_frame, text="Protocol:", style="Console.TLabel").pack(side="left", padx=(0, 5))
        protocol_menu = ttk.OptionMenu(self.top_frame, self.protocol, "SSH", "SSH", "Telnet", "Serial")
        protocol_menu.pack(side="left")

        ttk.Label(self.top_frame, text="Address:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.address).pack(side="left", padx=(0, 5))

        ttk.Label(self.top_frame, text="Port (TCP/Serial):", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.port, width=5).pack(side="left", padx=(0, 5))

        ttk.Label(self.top_frame, text="Baud Rate:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.baud_rate, width=8).pack(side="left", padx=5                                                                )

        ttk.Label(self.top_frame, text="COM Port:", style="Console.TLabel").pack(side="left", padx=(10, 5))
        ttk.Entry(self.top_frame, textvariable=self.com_port, width=8).pack(side="left", padx=5)

        ttk.Button(self.top_frame, text="Connect", style="Console.TButton", command=self.connect).pack(side="left", padx=5)
        ttk.Button(self.top_frame, text="Disconnect", style="Console.TButton", command=self.disconnect).pack(side="left", padx=5)

        guidance_image = Image.open("assets/guidance.png")
        guidance_image = guidance_image.resize((40, 40))
        guidance_icon = ImageTk.PhotoImage(guidance_image)

        new_button = Button(self.top_frame, image=guidance_icon, bd=1, bg="#2c2c2c", highlightthickness=0, activebackground='#181818', command=lambda: print("Button clicked!"))
        new_button.image = guidance_icon
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
        self.command_input.bind("<Up>", self.navigate_history_up)
        self.command_input.bind("<Down>", self.navigate_history_down)

    def connect(self):
        protocol = self.protocol.get().lower()
        address = self.address.get()
        port = self.port.get()

        if protocol == "serial":
            threading.Thread(target=self.start_serial_connection, args=(self.com_port.get(), self.baud_rate.get()), daemon=True).start()
        elif protocol == "ssh":
            threading.Thread(target=self.start_ssh_connection, args=(address, int(port)), daemon=True).start()
        elif protocol == "telnet":
            threading.Thread(target=self.start_telnet_connection, args=(address, int(port)), daemon=True).start()
        else:
            self.append_output("Unsupported protocol.")

    def disconnect(self):
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
        self.password_attempted = False
        self.append_output("Disconnected.")

    def start_ssh_connection(self, address, port):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.append_output(f"Connecting to {address} via SSH...")
            self.client.connect(address, port=port, username=None, password=None)
            self.append_output("SSH connection established.")
            self.shell = self.client.invoke_shell()
            self.password_attempted = False
            threading.Thread(target=self.read_ssh_output, daemon=True).start()
        except Exception as e:
            self.append_output(f"SSH connection failed: {e}")

    def read_ssh_output(self):
        buffer = ""
        while self.shell:
            try:
                data = self.shell.recv(1024).decode("utf-8")
                if data:
                    buffer += data
                    self.append_output(data)

                    if "username:" in buffer.lower() and not self.password_attempted:
                        self.shell.send(self.command_input.get() + "\n")
                        buffer = ""
                    elif "password:" in buffer.lower() and not self.password_attempted:
                        self.shell.send(self.command_input.get() + "\n")
                        self.password_attempted = True
                        buffer = ""
            except Exception as e:
                self.append_output(f"SSH read error: {e}")
                break

    def start_telnet_connection(self, address, port):
        try:
            self.telnet = telnetlib.Telnet(address, port, timeout=10)
            self.append_output(f"Connecting to {address} via Telnet...")
            threading.Thread(target=self.read_telnet_output, daemon=True).start()
        except Exception as e:
            self.append_output(f"Telnet connection failed: {e}")

    def read_telnet_output(self):
        buffer = ""
        try:
            while self.telnet:
                data = self.telnet.read_very_eager().decode("ascii")
                if data:
                    buffer += data
                    self.append_output(data)

                    if "username:" in buffer.lower():
                        self.append_output("Username prompt detected. Please type your username and press Enter.")
                        buffer = ""
                    elif "password:" in buffer.lower():
                        self.append_output("Password prompt detected. Please type your password and press Enter.")
                        buffer = ""
        except Exception as e:
            self.append_output(f"Telnet read error: {e}")

    def start_serial_connection(self, com_port, baud_rate):
        try:
            self.serial_conn = serial.Serial(com_port, baud_rate, timeout=1)
            self.append_output(f"Serial connection established on {com_port} at {baud_rate} baud.")
            threading.Thread(target=self.read_serial_output, daemon=True).start()
        except Exception as e:
            self.append_output(f"Serial connection failed: {e}")

    def read_serial_output(self):
        buffer = ""
        while self.serial_conn:
            try:
                data = self.serial_conn.readline().decode("utf-8")
                if data:
                    buffer += data
                    self.append_output(data)
            except Exception as e:
                self.append_output(f"Serial read error: {e}")
                break

    def handle_input(self, event):
        command = self.command_input.get().strip()

        if command.lower() == "clear":
            self.output_text.config(state="normal")
            self.output_text.delete(1.0, tk.END)
            self.output_text.config(state="disabled")
            self.command_input.delete(0, tk.END)
            return "break"

        if command:
            self.append_output(f"> {command}")
            protocol = self.protocol.get().lower()
            if protocol == "serial":
                self.send_serial_command(command)
            elif protocol == "ssh" or protocol == "telnet":
                self.send_command(command)
                self.command_history.append(command)
                if len(self.command_history) > self.max_command_history:
                    self.command_history.pop(0)
                self.history_index = len(self.command_history)
            self.command_input.delete(0, tk.END)
        else:
            self.send_enter_key()

        self.output_text.yview("end")

        return "break"

    def navigate_history_up(self, event):
        if self.history_index > 0:
            self.history_index -= 1
            self.command_input.delete(0, tk.END)
            self.command_input.insert(0, self.command_history[self.history_index])

    def navigate_history_down(self, event):
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_input.delete(0, tk.END)
            self.command_input.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index += 1
            self.command_input.delete(0, tk.END)

    def send_enter_key(self):
        protocol = self.protocol.get().lower()

        if protocol == "serial" and self.serial_conn:
            self.serial_conn.write(b"\n")
        elif protocol == "ssh" and self.shell:
            self.shell.send(b"\n")
        elif protocol == "telnet" and self.telnet:
            try:
                self.telnet.sock.send(b'')
                self.telnet.write(b"\n")
            except Exception as e:
                self.append_output(f"Telnet connection error: {e}")
                self.telnet = None

    def send_command(self, command):
        if self.shell:
            self.shell.send(command + "\n")
        elif self.telnet:
            self.telnet.write(command.encode("ascii") + b"\n")

    def send_serial_command(self, command):
        if self.serial_conn:
            self.serial_conn.write(command.encode("utf-8") + b"\n")

    def stop_scanning_when_leaving(self):
        self.stop_scanning()

    def append_output(self, text):
        self.output_text.config(state="normal")
        self.output_text.insert("end", text + "\n")
        self.output_text.config(state="disabled")
        self.output_text.yview("end")

def navigate_to_console(main_frame, stop_scanning):
    for widget in main_frame.winfo_children():
        widget.destroy()

    console = Console(main_frame, stop_scanning)
    return console
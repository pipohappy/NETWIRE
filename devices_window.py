import tkinter as tk
from tkinter import ttk, font
import threading
from netinfo2 import nmap_scan  # Import the port scan function
from netinfo import unified_device_scan, add_device_to_tree
from devices_history import save_scan
from networkspeed import start_speed_test

is_scanning = [False]
is_port_scanning = [False]  # Flag to manage port scanning state

def navigate_to_devices(main_frame):
    global device_tree, port_scan_text, is_scanning, scan_button, is_port_scanning

    # Reset style for Treeview
    style = ttk.Style()
    style.configure("Treeview", font=("Arial", 10, "normal"), foreground='#cccccc')

    # Clear existing widgets
    for widget in main_frame.winfo_children():
        widget.destroy()

    # Configure main frame layout
    main_frame.columnconfigure(0, weight=1)
    main_frame.columnconfigure(1, weight=2)
    main_frame.rowconfigure(0, weight=1)

    # Left frame for controls and device list
    left_frame = ttk.Frame(main_frame, style="Main.TFrame")
    left_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

    # IP Range Entry
    ip_range_label = ttk.Label(left_frame, text="IP Range:", style="Main.TLabel")
    ip_range_label.pack(pady=10, anchor="w")

    ip_range_entry = tk.Entry(left_frame)
    ip_range_entry.insert(0, "192.168.0.0/24")
    ip_range_entry.pack(pady=10, fill="x", anchor="w")

    # Buttons for scanning and saving
    button_frame = ttk.Frame(left_frame, style="Main.TFrame")
    button_frame.pack(pady=10, fill="x")

    scan_button = ttk.Button(button_frame, text="Start Scan", style="Main.TButton")
    scan_button.pack(side="left", expand=True, fill="x", padx=(0, 5))

    save_scan_button = ttk.Button(button_frame, text="Save Scan", style="Main.TButton", command=lambda: save_scan(device_tree))
    save_scan_button.pack(side="left", expand=True, fill="x")

    # TreeView to display scanned devices
    device_tree = ttk.Treeview(left_frame, columns=("IP", "MAC", "Brand"), show="headings", style="Treeview")
    device_tree.heading("IP", text="IP Address")
    device_tree.heading("MAC", text="MAC Address")
    device_tree.heading("Brand", text="Brand")
    device_tree.pack(pady=10, fill="both", expand=True)

    # Right frame for port scanning and speed test
    right_frame = ttk.Frame(main_frame, style="Main.TFrame")
    right_frame.grid(row=0, column=1, sticky="nsew", padx=10)

    right_frame.rowconfigure(1, weight=1)
    right_frame.rowconfigure(2, weight=0)
    right_frame.columnconfigure(0, weight=1)

    # Port Scanning Text Box
    top_right_frame = ttk.Frame(right_frame, style="Main.TFrame")
    top_right_frame.grid(row=0, column=0, sticky="nsew", padx=10)

    port_scan_text = tk.Text(top_right_frame, wrap="word", state="disabled", background="#2c2c2c", foreground="white")
    port_scan_text.pack(fill="both", expand=True, padx=10, pady=10)

    # Clear Port Scan Results Button
    def clear_port_scan_results():
        port_scan_text.config(state="normal")
        port_scan_text.delete(1.0, tk.END)  # Clear all results
        port_scan_text.config(state="disabled")

    clear_button = ttk.Button(top_right_frame, text="Clear Results", style="Main.TButton", command=clear_port_scan_results)
    clear_button.pack(pady=10)

    # Speed Test Section
    speed_test_frame = ttk.Frame(right_frame, style="Main.TFrame")
    speed_test_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

    large_font = font.Font(size=56)
    speed_test_label = ttk.Label(speed_test_frame, text="Speed Test", style="Main.TLabel", font=large_font)
    speed_test_label.pack(pady=(10, 5))

    loading_label = ttk.Label(speed_test_frame, text="", style="Main.TLabel")
    loading_label.pack(pady=10)

    result_label = ttk.Label(speed_test_frame, style="Main.TLabel")
    result_label.pack(pady=10)

    speed_test_button = ttk.Button(
        speed_test_frame,
        text="Run Speed Test",
        command=lambda: start_speed_test(loading_label, result_label),
        style="Main.TButton",
    )
    speed_test_button.pack(pady=10, padx=10, fill="x")

    # Wrapper for running device scan
    def run_scans_wrapper():
        unified_device_scan(
            ip_range=ip_range_entry.get(),
            is_scanning=is_scanning,
            device_tree=device_tree,
            add_device_to_tree=add_device_to_tree
        )

    # Port scan function
    def run_port_scan(ip):
        port_scan_result = nmap_scan(ip)  # Perform port scan using nmap_scan
        port_scan_text.config(state="normal")
        port_scan_text.insert(tk.END, f"Port scan results for {ip}:\n")  # Add a header for each scan
        port_scan_text.insert(tk.END, f"{port_scan_result}\n")  # Append the scan result
        port_scan_text.insert(tk.END, "-"*50 + "\n")  # Add a separator
        port_scan_text.config(state="disabled")

    # Start Port Scan thread
    def start_port_scan_thread(ip):
        threading.Thread(target=run_port_scan, args=(ip,), daemon=True).start()

    # Toggle the scan state (device scan)
    def toggle_scan_state():
        if not is_scanning[0]:  # Only toggle if not currently scanning
            is_scanning[0] = True
            scan_button.config(text="Stop Scan")
            threading.Thread(target=run_scans_wrapper, daemon=True).start()
        else:
            is_scanning[0] = False
            scan_button.config(text="Start Scan")

    scan_button.config(command=toggle_scan_state)

    # Stop scanning and port scanning when leaving the device window
    def stop_scanning():
        if is_scanning[0]:
            is_scanning[0] = False
            scan_button.config(text="Start Scan")
        if is_port_scanning[0]:
            is_port_scanning[0] = False
            port_scan_text.config(state="normal")
            port_scan_text.insert(tk.END, "\nScanning stopped.\n")
            port_scan_text.config(state="disabled")
        print("Scanning stopped due to navigation.")

    main_frame.bind("<Destroy>", lambda event: stop_scanning())

    # Handle device click in the tree (start port scan for that device)
    def on_device_click(event):
        selected_item = device_tree.selection()
        if selected_item:
            item_id = selected_item[0]
            ip = device_tree.item(item_id, "values")[0]  # Get the IP of the selected device
            if not is_port_scanning[0]:
                is_port_scanning[0] = True
            start_port_scan_thread(ip)

    device_tree.bind("<Double-1>", on_device_click)  # Bind double-click to start the port scan

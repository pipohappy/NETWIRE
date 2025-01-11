import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import scapy.all as scapy
import psutil
from PIL import Image, ImageTk
import threading
import time
import os


capturing = [False]
captured_packets = []
reload_icon = None
capture_thread = None
active_filter = []
in_traffic_window = False  # Track if we are in the traffic window

# Protocol-to-color mapping
PROTOCOL_COLORS = {
    "TCP": "#FF9999",   # Light Red
    "UDP": "#99CCFF",   # Light Blue
    "HTTP": "#CCFF99",  # Light Green
    "ICMP": "#FFCC66",  # Light Orange
    "DNS": "#FF99CC",   # Pink
    "ARP": "#CCCCFF",   # Light Purple
    "IP": "#FFFF99",    # Light Yellow
    "IPv6": "#99FFCC",  # Light Aqua
    "Unknown": "#CCCCCC"  # Gray for unknown protocols
}

def start_packet_capture():
    global captured_packets, selected_interface
    captured_packets = []
    capturing[0] = True  # Ensure capture is set to True

    # Get the selected interface from the dropdown
    selected_interface_name = selected_interface.get()

    # Check if an interface is selected
    if selected_interface_name == "Select Interface":
        messagebox.showerror("Error", "Please select an interface to capture packets.")
        capturing[0] = False  # Stop the capture
        return

    # Start the capture on the selected interface
    capture_traffic(selected_interface_name)

def capture_traffic(interface_name):
    def capture():
        packet_count = 0
        try:
            while capturing[0]:
                if interface_name.startswith("lo"):
                    # Use a different approach to capture packets on loopback interfaces
                    packet = scapy.sniff(count=1, filter="ip and not ip6")[0]
                else:
                    packet = scapy.sniff(iface=interface_name, count=1)[0]
                captured_packets.append(packet)
                packet_count += 1

                # Check if the packet matches the current active filter
                if packet_matches_filter(packet, active_filter):
                    protocol, source_ip, destination_ip, length, info = get_packet_info(packet)

                    # Safely update UI from the main thread
                    traffic_tree.after(
                        0,
                        lambda p=packet_count, prot=protocol, src=source_ip, dst=destination_ip, l=length, i=info:
                        insert_packet_data(p, prot, src, dst, l, i),
                    )
                time.sleep(0.1)  # Control packet capture speed
        except OSError as e:
            print(f"Error capturing packets: {e}")
            messagebox.showerror("Error", f"Failed to capture packets: {str(e)}")

    global capture_thread
    if not capturing[0]:
        return
    capture_thread = threading.Thread(target=capture, daemon=True)
    capture_thread.start()

def stop_packet_capture():
    capturing[0] = False  # Signal the thread to stop
    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=1)  # Wait a bit for thread to exit (non-blocking)

def toggle_capture_state(button):
    global reload_icon, reload_button
    if capturing[0]:
        capturing[0] = False
        stop_packet_capture()
        button.config(text="Start Capture")
    else:
        capturing[0] = True
        start_packet_capture()
        button.config(text="Stop Capture")

def erase_captured_traffic():
    """Erase captured traffic and clear the treeview."""
    global captured_packets
    captured_packets.clear()
    traffic_tree.delete(*traffic_tree.get_children())
    messagebox.showinfo("Erase Successful", "Captured traffic erased successfully.")

def insert_packet_data(packet_count, protocol, source_ip, destination_ip, length, info):
    if traffic_tree.winfo_exists():  # Check if the widget still exists
        color = PROTOCOL_COLORS.get(protocol, "#FFFFFF")
        traffic_tree.insert(
            '', 'end', text=str(packet_count), values=(protocol, source_ip, destination_ip, length, info),
            tags=(protocol,)
        )
        traffic_tree.tag_configure(protocol, background=color)

# Traffic Filtering Functions
def apply_filter():
    global active_filter
    filter_text = filter_entry.get().strip().lower()
    filter_terms = [term.strip() for term in filter_text.split(",") if term.strip()]

    if not filter_terms:
        active_filter = []
        traffic_tree.delete(*traffic_tree.get_children())
        for i, packet in enumerate(captured_packets):
            protocol, source_ip, destination_ip, length, info = get_packet_info(packet)
            color = PROTOCOL_COLORS.get(protocol, "#FFFFFF")  # Get color for protocol
            traffic_tree.insert(
                '', 'end', text=str(i+1), values=(protocol, source_ip, destination_ip, length, info),
                tags=(protocol,)
            )
            traffic_tree.tag_configure(protocol, background=color)  # Apply color
        return

    for term in filter_terms:
        clean_term = term.replace("not ", "").replace("exc ", "").strip()
        if not is_valid_filter(clean_term):
            messagebox.showerror("Incorrect Syntax", f"The filter '{term}' contains invalid syntax.")
            return

    active_filter = filter_terms

    traffic_tree.delete(*traffic_tree.get_children())
    for i, packet in enumerate(captured_packets):
        if packet_matches_filter(packet, filter_terms):
            protocol, source_ip, destination_ip, length, info = get_packet_info(packet)
            color = PROTOCOL_COLORS.get(protocol, "#FFFFFF")  # Get color for protocol
            traffic_tree.insert(
                '', 'end', text=str(i+1), values=(protocol, source_ip, destination_ip, length, info),
                tags=(protocol,)
            )
            traffic_tree.tag_configure(protocol, background=color)  # Apply color

def is_valid_filter(term):
    valid_protocols = ["arp", "dns", "icmp", "tcp", "udp", "ip", "ipv6"]
    if term.lower() in valid_protocols:
        return True
    if term.count(".") == 3 or ":" in term:  # IPv4 or IPv6 simple check
        return True
    return False

def packet_matches_filter(packet, filter_terms):
    if not filter_terms:
        return True

    protocol, source_ip, destination_ip, _, info = get_packet_info(packet)
    packet_included = True
    match_found = False

    for term in filter_terms:
        exclude = term.startswith("not ")
        exception = " exc " in term

        # Handle "dst" with multiple IPs
        if term.startswith("dst "):
            dst_ips = term[4:].split(",")  # Split by commas for multiple IPs
            dst_ips = [ip.strip() for ip in dst_ips]  # Clean extra spaces around IPs

            if any(dst_ip.lower() == destination_ip.lower() for dst_ip in dst_ips):
                match_found = True
            else:
                packet_included = False
            continue

        # Handle "src" with multiple IPs
        elif term.startswith("src "):
            src_ips = term[4:].split(",")  # Split by commas for multiple IPs
            src_ips = [ip.strip() for ip in src_ips]  # Clean extra spaces around IPs

            if any(src_ip.lower() == source_ip.lower() for src_ip in src_ips):
                match_found = True
            else:
                packet_included = False
            continue

        # Handle "exc" (exception) filter logic
        if exception:
            exc_parts = term.split(" exc ")
            clean_term = exc_parts[0].replace("not ", "").strip()
            exc_protocol = exc_parts[1].strip()
            match = clean_term in source_ip.lower() or clean_term in destination_ip.lower()
            if match and protocol.lower() == exc_protocol.lower():
                return True
            continue

        else:
            clean_term = term.replace("not ", "").strip()
            match = (
                clean_term in protocol.lower()
                or clean_term in source_ip.lower()
                or clean_term in destination_ip.lower()
                or clean_term in info.lower()
            )
            if exclude:
                if match:
                    packet_included = False
            else:
                if match:
                    match_found = True

    return packet_included and (match_found or any(term.startswith("not ") for term in filter_terms))

def show_packet_details(packet):
    details_window = tk.Toplevel()
    details_window.title(f"Packet Details")

    text_widget = tk.Text(details_window, wrap="word", background="#2c2c2c", foreground="white")
    text_widget.pack(fill="both", expand=True)

    # Insert the packet details into the text widget
    # This will use scapy's show() method to dump the packet details in a readable format
    text_widget.insert('end', packet.show(dump=True))

def on_tree_item_click(event):
    selected_item = traffic_tree.selection()
    if selected_item:
        item_id = selected_item[0]
        item_index = traffic_tree.index(item_id)  # Get the index of the selected item
        
        if 0 <= item_index < len(captured_packets):
            selected_packet = captured_packets[item_index]
            show_packet_details(selected_packet)
        else:
            messagebox.showwarning("Warning", "Selected item index is out of range.")

# Packet Information
def get_packet_info(packet):
    if packet.haslayer(scapy.ARP):
        protocol = "ARP"
    elif packet.haslayer(scapy.DNS):
        protocol = "DNS"
    elif packet.haslayer(scapy.ICMP):
        protocol = "ICMP"
    elif packet.haslayer(scapy.TCP):
        protocol = "TCP"
    elif packet.haslayer(scapy.UDP):
        protocol = "UDP"
    elif packet.haslayer(scapy.IP):
        protocol = "IP"
    elif packet.haslayer(scapy.IPv6):
        protocol = "IPv6"
    else:
        protocol = "Unknown"
    if packet.haslayer(scapy.ARP):
        source_ip = packet[scapy.ARP].psrc
        destination_ip = packet[scapy.ARP].pdst
    elif packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
    elif packet.haslayer(scapy.IPv6):
        source_ip = packet[scapy.IPv6].src
        destination_ip = packet[scapy.IPv6].dst
    else:
        source_ip = "N/A"
        destination_ip = "N/A"

    length = len(packet)
    info = packet.summary()

    return protocol, source_ip, destination_ip, length, info

def update_interface(header_frame, interface_name, captured_packets):
    """Update the network interface used for packet capture."""
    global capturing, capture_thread, selected_interface

    # Stop the current capture if it's running
    if capturing[0]:
        stop_packet_capture()

    # Show a warning message
    def save_packets():
        save_captured_traffic()
        warning_window.destroy()
        # Clear the captured packets
        global captured_packets
        captured_packets.clear()
        traffic_tree.delete(*traffic_tree.get_children())
        # Update the selected interface
        selected_interface.set(interface_name)
        # Update the button state to "Start Capture"
        for widget in header_frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget['text'] == "Stop Capture":
                widget['text'] = "Start Capture"

    def dont_save_packets():
        warning_window.destroy()
        # Clear the captured packets
        global captured_packets
        captured_packets.clear()
        traffic_tree.delete(*traffic_tree.get_children())
        # Update the selected interface
        selected_interface.set(interface_name)
        # Update the button state to "Start Capture"
        for widget in header_frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget['text'] == "Stop Capture":
                widget['text'] = "Start Capture"

    if len(captured_packets) > 0:
        warning_window = tk.Toplevel()
        warning_window.title("Warning")
        warning_window.configure(bg="#2c2c2c")  # Set the background color to match the app's color

        warning_frame = tk.Frame(warning_window, bg="#2c2c2c")
        warning_frame.pack(padx=10, pady=10)

        warning_label = tk.Label(warning_frame, text="Changing the interface will lose all captured packets. Do you want to save them?", bg="#2c2c2c", fg="white")
        warning_label.pack()

        button_frame = tk.Frame(warning_frame, bg="#2c2c2c")
        button_frame.pack()

        save_button = tk.Button(button_frame, text="Save", command=save_packets, bg="#4CAF50", fg="white")
        save_button.pack(side=tk.LEFT, padx=5)

        dont_save_button = tk.Button(button_frame, text="Don't Save", command=dont_save_packets, bg="#e74c3c", fg="white")
        dont_save_button.pack(side=tk.RIGHT, padx=5)
    else:
        # Clear the captured packets
        captured_packets.clear()
        traffic_tree.delete(*traffic_tree.get_children())
        # Update the selected interface
        selected_interface.set(interface_name)
        # Update the button state to "Start Capture"
        for widget in header_frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget['text'] == "Stop Capture":
                widget['text'] = "Start Capture"

def save_captured_traffic():
    save_directory = filedialog.askdirectory(title="Select Folder to Save PCAP")
    if save_directory:
        filename = f"traffic_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
        full_path = os.path.join(save_directory, filename)
        scapy.wrpcap(full_path, captured_packets)
        messagebox.showinfo("Save Successful", f"Traffic saved to {full_path}")

def load_captured_traffic():
    load_file = filedialog.askopenfilename(title="Select PCAP File to Load", filetypes=[("PCAP Files", "*.pcap")])
    if load_file:
        global captured_packets
        captured_packets = scapy.rdpcap(load_file)
        traffic_tree.delete(*traffic_tree.get_children())
        for i, packet in enumerate(captured_packets):
            protocol, source_ip, destination_ip, length, info = get_packet_info(packet)
            color = PROTOCOL_COLORS.get(protocol, "#FFFFFF")  # Get color for protocol
            traffic_tree.insert(
                '', 'end', text=str(i+1), values=(protocol, source_ip, destination_ip, length, info),
                tags=(protocol,)
            )
            traffic_tree.tag_configure(protocol, background=color)  # Apply color
            color = PROTOCOL_COLORS.get(protocol, "#FFFFFF")  # Get color for protocol
            traffic_tree.tag_configure(protocol, background=color)  # Apply color

def get_all_network_interfaces():
    """Get a list of all available network interfaces (including virtual ones)."""
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())  # Return all interface names

def navigate_to_traffic(main_frame, stop_scanning):
    global traffic_tree, save_button, filter_entry, in_traffic_window, selected_interface

    # Stop capturing if we are entering the traffic window
    if capturing[0]:
        stop_packet_capture()

    in_traffic_window = True  # Set the flag to indicate we are in the traffic window

    for widget in main_frame.winfo_children():
        widget.destroy()

    # Create header frame for buttons
    header_frame = ttk.Frame(main_frame, style="Main.TFrame")
    header_frame.pack(fill="x", padx=10, pady=10)

    # Create the Start/Stop Capture button
    capture_button = ttk.Button(
        header_frame, text="Start Capture", style="Main.TButton", command=lambda: toggle_capture_state(capture_button)
    )
    capture_button.pack(side="left", padx=10)

    # Create Save Capture button
    save_button = ttk.Button(
        header_frame, text="Save Capture", style="Main.TButton", command=save_captured_traffic
    )
    save_button.pack(side="left", padx=10)

    # Create Load Capture button
    load_button = ttk.Button(
        header_frame, text="Load Capture", style="Main.TButton", command=load_captured_traffic
    )
    load_button.pack(side="left", padx=10)

    # Create Erase Capture button
    erase_button = ttk.Button(
        header_frame, text="Erase Capture", style="Main.TButton", command=erase_captured_traffic
    )
    erase_button.pack(side="left", padx=10)

    # Add Dropdown for Interface Selection
    all_interfaces = get_all_network_interfaces()
    selected_interface = tk.StringVar()  # Ensure this is a tk.StringVar()
    selected_interface.set("Select Interface")  # Set the default value

    interface_dropdown = ttk.Combobox(header_frame, textvariable=selected_interface, values=all_interfaces, state="readonly", width=30)
    
    interface_dropdown.pack(side="left", padx=10)
    interface_dropdown.bind("<<ComboboxSelected>>", lambda event: update_interface(header_frame, selected_interface.get(), captured_packets))

    # Add Filter functionality
    filter_frame = ttk.Frame(header_frame)
    filter_frame.pack(side="left", padx=10)

    filter_label = ttk.Label(filter_frame, text="Filter:")
    filter_label.pack(side="left")

    filter_entry = ttk.Entry(filter_frame, width=30)
    filter_entry.pack(side="left", padx=5)

    filter_button = ttk.Button(
        filter_frame, text="Apply Filter", command=apply_filter
    )
    filter_button.pack(side="left")

    # Apply style to Treeview
    style = ttk.Style()
    style.configure("Treeview", font=("Helvetica", 10, "bold"), foreground="black")

    # Create the Treeview for captured traffic data
    columns = ("protocol", "source", "destination", "length", "info")
    traffic_tree = ttk.Treeview(main_frame, columns=columns, show="headings", style="Treeview")

    # Treeview configuration
    traffic_tree.heading("#1", text="Protocol")
    traffic_tree.heading("#2", text="Source IP")
    traffic_tree.heading("#3", text="Destination IP")
    traffic_tree.heading("#4", text="Length")
    traffic_tree.heading("#5", text="Info")

    traffic_tree.column("#1", width=100)
    traffic_tree.column("#2", width=150)
    traffic_tree.column("#3", width=150)
    traffic_tree.column("#4", width=80)
    traffic_tree.column("#5", width=300)

    traffic_tree.pack(fill="both", expand=True, padx=10, pady=10)

    # Bind double-click event to open packet details
    traffic_tree.bind("<Double-1>", on_tree_item_click)


import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Button
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import psutil
from PIL import Image, ImageTk
import threading
import time
import os
import re
import sys


capturing = [False]
captured_packets = []
logical_ops = ['and', 'or', 'not']
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

def apply_filter():
    global active_filter
    filter_text = filter_entry.get().strip().lower()

    if not filter_text:
        active_filter = []  # Clear filter if no input
        update_traffic_display()  # Show all captured packets
        return
    
    # Process the filter input and break it into conditions
    active_filter = parse_filters(filter_text)
    update_traffic_display()

def parse_filters(filter_expr):
    """Convert filter expression to a properly formatted list."""
    # Replace logical operators
    filter_expr = filter_expr.replace("!", " not ")
    filter_expr = filter_expr.replace("&&", " and ")
    filter_expr = filter_expr.replace("||", " or ")

    # Tokenize the expression and split by spaces
    filter_parts = filter_expr.strip().split()

    # Handle negation (`not`) correctly for conditions
    updated_filter_parts = []
    skip_next = False

    for i, part in enumerate(filter_parts):
        if skip_next:
            skip_next = False
            continue
        if part == "not" and i + 1 < len(filter_parts):
            updated_filter_parts.append("not " + filter_parts[i + 1])
            skip_next = True
        else:
            updated_filter_parts.append(part)
    
    return updated_filter_parts

# Update the display of captured traffic based on the filter
def update_traffic_display():
    traffic_tree.delete(*traffic_tree.get_children())  # Clear previous results
    for i, packet in enumerate(captured_packets):
        if packet_matches_filter(packet, active_filter):
            protocol, source_ip, destination_ip, length, info = get_packet_info(packet)
            color = PROTOCOL_COLORS.get(protocol, "#FFFFFF")  # Default color if not found
            traffic_tree.insert(
                '', 'end', text=str(i + 1), values=(protocol, source_ip, destination_ip, length, info),
                tags=(protocol,)
            )
            traffic_tree.tag_configure(protocol, background=color)  # Apply color

def check_src(packet, ip):
    """Check if the source IP matches."""
    return get_packet_info(packet)[1] == ip

def check_dst(packet, ip):
    """Check if the destination IP matches."""
    return get_packet_info(packet)[2] == ip

def check_port(packet, port):
    """Check if the port matches (TCP or UDP)."""
    return (packet.haslayer(TCP) and (packet.sport == port or packet.dport == port)) or \
           (packet.haslayer(UDP) and (packet.sport == port or packet.dport == port))

# def check_protocol(packet, proto):
#     if proto == "tcp":
#         return packet.haslayer(scapy.TCP)
#     elif proto == "udp":
#         return packet.haslayer(scapy.UDP)
#     elif proto == "icmp":
#         return packet.haslayer(scapy.ICMP)
#     elif proto == "arp":
#         return packet.haslayer(scapy.ARP)
#     elif proto == "dns":
#         return packet.haslayer(scapy.DNS)
#     elif proto == "ip":
#         return packet.haslayer(scapy.IP)
#     elif proto == "ipv6":
#         return packet.haslayer(scapy.IPv6)
#     else:
#         return False
def check_protocol(packet, proto):
    protocol, _, _, _, _ = get_packet_info(packet)
    return protocol.lower() == proto.lower()

def check_ip(packet, ip, direction="src"):
    """General function to check source or destination IP."""
    packet_info = get_packet_info(packet)
    if direction == "src":
        return packet_info[1] == ip
    elif direction == "dst":
        return packet_info[2] == ip
    return False

def packet_matches_filter(packet, filters):
    try:
        if not filters:
            return True  # No filter applied, show all packets

        condition_string = " ".join(filters)

        # Match standalone IPv4 addresses
        ipv4_match = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', condition_string)
        if ipv4_match:
            return check_ip(packet, condition_string, "src") or check_ip(packet, condition_string, "dst")

        # Match standalone IPv6 or MAC
        if check_mac_or_ipv6(packet, condition_string):
            return True

        # Apply existing filter transformations
        condition_string = re.sub(r'\bsrc\s([\d\.]+)\b', r'check_src(packet, "\1")', condition_string)
        condition_string = re.sub(r'\bdst\s([\d\.]+)\b', r'check_dst(packet, "\1")', condition_string)
        condition_string = re.sub(r'\bport\s(\d+)\b', r'check_port(packet, \1)', condition_string)

        # Check protocol
        protocol, _, _, _, _ = get_packet_info(packet)
        condition_string = re.sub(r'\b(tcp|udp|icmp|arp|dns|ip|ipv6)\b', r'check_protocol(packet, "\1")', condition_string)

        print(f"Evaluating condition: {condition_string}")
        return eval(condition_string, {
            "packet": packet, 
            "check_src": check_src, 
            "check_dst": check_dst, 
            "check_port": check_port, 
            "check_protocol": check_protocol,
            "check_mac_or_ipv6": check_mac_or_ipv6
        })

    except Exception as e:
        print(f"Error in filter evaluation: {e}")
        return False

def check_mac_or_ipv6(packet, value):
    """Check if it's a MAC address or an IPv6 address."""
    # Check MAC addresses
    if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', value):  
        return (packet.haslayer(scapy.Ether) and 
                (packet[scapy.Ether].src == value or packet[scapy.Ether].dst == value))
    
    # Check IPv6 addresses
    if ":" in value:  
        return (packet.haslayer(scapy.IPv6) and 
                (packet[scapy.IPv6].src == value or packet[scapy.IPv6].dst == value))

    return False  # Not a match

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

        # Get the filtered packets from the captured_packets list
        filtered_packets = []
        for packet in captured_packets:
            if packet_matches_filter(packet, active_filter):
                filtered_packets.append(packet)

        scapy.wrpcap(full_path, filtered_packets)
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
        header_frame, text="Start Capture", style="Traffic.TButton", command=lambda: toggle_capture_state(capture_button)
    )
    capture_button.pack(side="left", padx=10)

    # Create Save Capture button
    save_button = ttk.Button(
        header_frame, text="Save Capture", style="Traffic.TButton", command=save_captured_traffic
    )
    save_button.pack(side="left", padx=10)

    # Create Load Capture button
    load_button = ttk.Button(
        header_frame, text="Load Capture", style="Traffic.TButton", command=load_captured_traffic
    )
    load_button.pack(side="left", padx=10)

    # Create Erase Capture button
    erase_button = ttk.Button(
        header_frame, text="Erase Capture", style="Traffic.TButton", command=erase_captured_traffic
    )
    erase_button.pack(side="left", padx=10)

    def resource_path(relative_path):
        """ Get the absolute path to a resource bundled with PyInstaller """
        try:
            # PyInstaller creates a temporary folder and stores the resources there
            base_path = sys._MEIPASS
        except Exception:
            # If running normally, use the current directory
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    # Add Dropdown for Interface Selection
    all_interfaces = get_all_network_interfaces()
    selected_interface = tk.StringVar()  # Ensure this is a tk.StringVar()
    selected_interface.set("Select Interface")  # Set the default value

    interface_dropdown = ttk.Combobox(header_frame, textvariable=selected_interface, values=all_interfaces, state="readonly", width=30, style="Filter.TCombobox")
    
    interface_dropdown.pack(side="left", padx=10)
    interface_dropdown.bind("<<ComboboxSelected>>", lambda event: update_interface(header_frame, selected_interface.get(), captured_packets))

    def reset_filter():
        global active_filter
        filter_entry.delete(0, tk.END)  # Clear the filter entry
        active_filter = []  # Clear active filter
        update_traffic_display()  # Update the display to show all packets

    # Add Filter functionality
    filter_frame = ttk.Frame(header_frame)
    filter_frame.pack(side="left", padx=10)

    filter_label = ttk.Label(filter_frame, text="Filter:", style="Traffic.TLabel")
    filter_label.pack(side="left")

    filter_entry = ttk.Entry(filter_frame, width=30, foreground="White")
    filter_entry.pack(side="left", padx=5)

    # Apply Filter button
    filter_button = ttk.Button(
        filter_frame, text="Apply Filter", style="Traffic2.TButton", command=apply_filter)
    filter_button.pack(side="left")

    # Reset Filter button (new button)
    reset_button = ttk.Button(
        filter_frame, text="Reset Filter", style="Traffic2.TButton", command=reset_filter)
    reset_button.pack(side="left", padx=5)

    guidance_image = Image.open(resource_path("assets/guidance.png")) # Replace with your image path
    guidance_image = guidance_image.resize((40, 40))
    guidance_icon = ImageTk.PhotoImage(guidance_image)

    # New button with an image
    new_button = Button(header_frame, image=guidance_icon, bd=1, bg="#2c2c2c", highlightthickness=0, activebackground='#181818', command=lambda: print("Button clicked!"))
    new_button.image = guidance_icon  # Keep a reference to avoid garbage collection
    new_button.pack(side="right", padx=(5, 0))

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


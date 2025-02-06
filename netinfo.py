import requests
import subprocess
from scapy.all import ARP, Ether, srp, conf
import threading
import time
import socket

def get_default_gateway_ip():
    """Get the default gateway's IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def get_ip_range(ip):
    """Calculate the IP range based on the default gateway's IP address"""
    # Assuming a /24 subnet mask (255.255.255.0)
    ip_parts = ip.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    return ip_range

def unified_device_scan(is_scanning, device_tree, add_device_to_tree, interval=5):
    ip_range = get_ip_range(get_default_gateway_ip())

    def get_device_brand(mac_address):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}")
            if response.status_code == 200:
                return response.text
        except requests.RequestException as e:
            print(f"MAC Vendor API request failed: {e}")
        return "Unknown"

    def get_device_brands(devices):
        device_brands = {}
        threads = []

        def get_brand(mac_address):
            brand = get_device_brand(mac_address)
            device_brands[mac_address] = brand

        for device in devices:
            thread = threading.Thread(target=get_brand, args=(device["mac"],))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return device_brands

    def scan():
        while is_scanning[0]:  # Continue scanning while the flag is True
            devices = []

            # ARP request
            try:
                arp = ARP(pdst=ip_range)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                conf.verb = 0
                result = srp(packet, timeout=3, verbose=0)[0]
                for sent, received in result:
                    mac_address = received.hwsrc
                    devices.append({"ip": received.psrc, "mac": mac_address})
            except Exception as e:
                print(f"Error during ARP scan: {e}")

            # ICMP Ping
            ip_base = ip_range.rsplit('.', 1)[0]
            for i in range(1, 255):  # Adjust for subnet size
                ip = f"{ip_base}.{i}"
                if not any(d["ip"] == ip for d in devices):  # Skip if already found
                    if ping_device(ip):
                        devices.append({"ip": ip, "mac": "Unknown"})

            # Get device brands in parallel
            device_brands = get_device_brands(devices)

            # Update device information with brands
            for device in devices:
                device["brand"] = device_brands.get(device["mac"], "Unknown")

            if is_scanning[0]:  # Check before updating the UI
                device_tree.after(0, lambda: update_device_tree(devices, device_tree, add_device_to_tree))
            else:
                print("Scan thread exiting.")
                break

            time.sleep(interval)  # Wait before the next scan

    threading.Thread(target=scan, daemon=True).start()

def ping_device(ip):
    try:
        response = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
        return response.returncode == 0
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return False

def update_device_tree(devices, device_tree, add_device_to_tree):
    try:
        if device_tree.winfo_exists():  # Check if widget exists
            device_tree.delete(*device_tree.get_children())  # Clear previous results
            for device in devices:
                add_device_to_tree(device, device_tree)
    except Exception as e:
        print(f"Error updating device tree: {e}")

def add_device_to_tree(device, device_tree):
    device_tree.insert('', 'end', values=(device["ip"], device["mac"], device["brand"]))
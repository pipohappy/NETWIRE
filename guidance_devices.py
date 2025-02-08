import tkinter as tk
from tkinter import ttk
import sys
import os
import webbrowser
from PIL import Image, ImageTk

def resource_path(relative_path):
    """ Get the absolute path to a resource bundled with PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def guidance_of_devices():
    """Displays the guidance window with instructions and header."""
    guidance_win = tk.Toplevel()
    guidance_win.title("Guidance")
    guidance_win.configure(bg='#2c2c2c')
    guidance_win.attributes("-fullscreen", True)

    fs_image = Image.open(resource_path("assets/sff.png"))
    fs_image = fs_image.resize((37, 24))
    fs_icon = ImageTk.PhotoImage(fs_image)

    style = ttk.Style()
    style.configure("Header.TFrame", background='#181818')
    style.configure("Header.TButton", background='#181818', foreground="white", font=("Arial", 16, "bold"), borderwidth=0)
    style.map("Header.TButton", background=[('active', '#2c2c2c')], foreground=[('active', 'white')])

    header_frame = ttk.Frame(guidance_win, style="Header.TFrame")
    header_frame.pack(fill="x")

    close_button = ttk.Button(header_frame, text="X", style="Header.TButton", command=guidance_win.destroy, width=3)
    close_button.pack(side="right")

    def toggle_full_screen(guidance_win):
        guidance_win.attributes("-fullscreen", not guidance_win.attributes("-fullscreen"))

    toggle_fs_button = ttk.Button(header_frame, image=fs_icon, style="Header.TButton", command=lambda: toggle_full_screen(guidance_win))
    toggle_fs_button.image = fs_icon
    toggle_fs_button.pack(side="right")

    minimize_button = ttk.Button(header_frame, text="_", style="Header.TButton", command=guidance_win.iconify, width=3)
    minimize_button.pack(side="right")

    stay_on_top_var = tk.BooleanVar()
    
    def print_selection():
        """Callback function to toggle the stay-on-top feature."""
        if stay_on_top_var.get():
            guidance_win.attributes("-topmost", True)
        else:
            guidance_win.attributes("-topmost", False)
    
    stay_on_top_checkbox = tk.Checkbutton(
        header_frame, text="Stay on top", variable=stay_on_top_var,
        onvalue=True, offvalue=False, command=print_selection,
        bg="#181818", fg="white", selectcolor="#2c2c2c"
    )
    stay_on_top_checkbox.pack(side="left", padx=10)

    netwire_label = ttk.Label(guidance_win, text="NetWire", font=("Arial", 40, "bold"), foreground="orange", background='#2c2c2c', justify="center")
    netwire_label.pack(pady=20)

    guidance_text = (
        "Guidance for Using the Devices window\n\n"
        "What is This App For?\n\n"
        "This application is designed to scan a network for connected devices, retrieve detailed information about them, perform port scans, and test internet speed.\n\n"
        "How to Use the App\n\n"
        "1. Scanning for Devices\n- Click 'Start Scan' to detect devices on your network.\n- The scan retrieves the IP Address, MAC Address, and Device Brand.\n- Once complete, detected devices will be listed.\n\n"
        "2. Saving Scan Results\n- Click 'Save Scan' to store results for future reference.\n\n"
        "3. Performing a Port Scan\n- Double-click on a device to start a port scan.\n- The results display open ports and running services.\n- Click 'Clear Results' to remove previous scan data.\n\n"
        "4. Running a Speed Test\n- Click 'Run Speed Test' to measure internet speed.\n- The results show download and upload speeds.\n\n"
        "How the App Gathers Information\n\n"
        "- **Device Discovery:** Uses ARP and ICMP (ping) scans to find devices.\n"
        "- **Device Details:** Retrieves MAC addresses and identifies manufacturers via API lookup.!!!Most of the time the brand doesn't show\n"
        "- **Port Scanning:** Uses Nmap to scan for open ports and running services.\n"
        "- **Speed Test:** Sends and receives data packets to calculate download and upload speeds.\n"
        "\n**Learn More About Protocols**\n"
        "Visit the following websites to learn more about protocols and networks:\n"
        "* IANA (Internet Assigned Numbers Authority)\n"
        "* Wireshark\n"
        "* Cisco Netacad\n"
    )

   # Create a Frame to hold the text and image together
    content_frame = ttk.Frame(guidance_win, style="Header.TFrame")
    content_frame.pack(padx=20, pady=20, fill="both", expand=True)

    # Adjust font size of the guidance text and align it to the left
    guidance_label = tk.Label(content_frame, text=guidance_text, font=("Arial", 14), foreground="white", background='#2c2c2c', justify="left", anchor="w", wraplength=700)
    guidance_label.pack(side="left", anchor="w", padx=20)

    # Load and place one image on the right side
    img1 = ImageTk.PhotoImage(Image.open(resource_path("assets/devices_pic.png")).resize((1100, 800)))
    
    img_frame = ttk.Frame(content_frame, style="Header.TFrame")
    img_frame.pack(side="right", padx=10, pady=10)

    label1 = tk.Label(img_frame, image=img1, bg="#2c2c2c")
    label1.image = img1
    label1.pack(side="top", padx=10, pady=10)

   # Create links to websites
    links_frame = ttk.Frame(img_frame, style="Header.TFrame")
    links_frame.pack(side="bottom", padx=10, pady=10)

    iana_link = tk.Button(links_frame, text="IANA", command=lambda: webbrowser.open("https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=10, height=2)
    iana_link.pack(side="left", padx=10)

    wireshark_link = tk.Button(links_frame, text="Wireshark", command=lambda: webbrowser.open("https://www.wireshark.org/"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=10, height=2)
    wireshark_link.pack(side="left", padx=10)

    cisco_link = tk.Button(links_frame, text="Cisco Netacad", command=lambda: webbrowser.open("https://www.netacad.com/"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=13, height=2)
    cisco_link.pack(side="left", padx=10)

    guidance_win.bind("<Escape>", lambda event: guidance_win.destroy())

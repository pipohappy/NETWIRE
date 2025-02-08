import tkinter as tk
from tkinter import ttk
import sys
import os
from PIL import Image, ImageTk
import webbrowser

def resource_path(relative_path):
    """ Get the absolute path to a resource bundled with PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def guidance_of_console():
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
        "**What You Can See in This Window and How to Use It**\n"
        "This window is a console interface that allows you to connect to a remote server using SSH or Telnet protocols.\n"
        "You can use the buttons at the top to connect and disconnect from the server.\n"
        "\n"
        "**Header**\n"
        "The header at the top of the window contains the following fields:\n"
        "* Protocol: Select the protocol to use (SSH or Telnet)\n"
        "* Address: Enter the server's address\n"
        "* Port: Enter the server's port number\n"
        "* Username: Enter the username for SSH connections (only required for SSH)\n"
        "* Password: Enter the password for SSH connections (only required for SSH)\n"
        "**How It Works**\n"
        "This console interface uses the paramiko library to establish SSH connections and the telnetlib library to establish Telnet connections.\n"
        "The output from the server is displayed in real-time, and the input field allows you to send commands to the server.\n"
        "\n"
        "**Learn More**\n"
        "For more information on SSH and Telnet protocols, visit the following websites:\n"
        "* SSH Servers:\n"
        "  + OpenSSH\n"
        "  + SSH.com\n"
        "* Telnet Servers:\n"
        "  + Telnet.org\n"
        "* Command Line Interfaces:\n"
        "  + Microsoft Command Prompt\n"
        "  + Linux Terminal"
        "  + macOS Terminal\n"
    )

    # Create a Frame to hold the text and image together
    content_frame = ttk.Frame(guidance_win, style="Header.TFrame")
    content_frame.pack(padx=20, pady=20, fill="both", expand=True)

    # Adjust font size of the guidance text and align it to the left
    guidance_label = tk.Label(content_frame, text=guidance_text, font=("Arial", 14), foreground="white", background='#2c2c2c', justify="left", anchor="w", wraplength=700)
    guidance_label.pack(side="left", anchor="w", padx=20)

    # Load and place one image on the right side
    img1 = ImageTk.PhotoImage(Image.open(resource_path("assets/console_pic.png")).resize((1100, 800)))
    
    img_frame = ttk.Frame(content_frame, style="Header.TFrame")
    img_frame.pack(side="right", padx=10, pady=10)

    label1 = tk.Label(img_frame, image=img1, bg="#2c2c2c")
    label1.image = img1
    label1.pack(side="top", padx=10, pady=10)

  # Create links to websites
    links_frame = ttk.Frame(img_frame, style="Header.TFrame")
    links_frame.pack(side="bottom", padx=10, pady=10)

    openssh_link = tk.Button(links_frame, text="OpenSSH", command=lambda: webbrowser.open("https://www.openssh.com/"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=10, height=2)
    openssh_link.pack(side="left", padx=10)

    sshcom_link = tk.Button(links_frame, text="SSH.com", command=lambda: webbrowser.open("https://www.ssh.com/"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=10, height=2)
    sshcom_link.pack(side="left", padx=10)

    telnetorg_link = tk.Button(links_frame, text="Telnet.org", command=lambda: webbrowser.open("https://www.telnet.org/"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=10, height=2)
    telnetorg_link.pack(side="left", padx=10)

    cmd_link = tk.Button(links_frame, text="Microsoft Command Prompt", command=lambda: webbrowser.open("https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=22, height=2)
    cmd_link.pack(side="left", padx=10)

    linux_terminal_link = tk.Button(links_frame, text="Linux Terminal", command=lambda: webbrowser.open("https://linuxjourney.com"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=12, height=2)
    linux_terminal_link.pack(side="left", padx=10)

    macos_terminal_link = tk.Button(links_frame, text="macOS Terminal", command=lambda: webbrowser.open("https://support.apple.com/guide/terminal/welcome/mac"), bg="#2c2c2c", fg="white", font=("Arial", 16), width=14, height=2)
    macos_terminal_link.pack(side="left", padx=10)

    guidance_win.bind("<Escape>", lambda event: guidance_win.destroy())
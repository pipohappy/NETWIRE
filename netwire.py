import tkinter as tk
import os
import sys
from tkinter import ttk
from ttkthemes import ThemedTk
from PIL import Image, ImageTk
import webbrowser
from devices_window import navigate_to_devices  # Import from devices_window.py
from traffic_window import navigate_to_traffic  # Use the complete version of navigate_to_traffic
from console import navigate_to_console

def create_styles(style):
    style.configure("Header.TFrame", background='#181818')
    style.configure("Header.TButton", background='#181818', foreground="white", font=("Arial", 16, "bold"), borderwidth=0)
    style.map("Header.TButton", background=[('active', '#2c2c2c')], foreground=[('active', 'white')])

    style.configure("NetWire.TButton", background='#181818', foreground="orange", font=("Arial", 18, "bold"), borderwidth=0)
    style.map("NetWire.TButton", background=[('active', '#2c2c2c')], foreground=[('active', 'orange')])

    style.configure("Sidebar.TFrame", background='#181818', relief="ridge", borderwidth=2)
    style.configure("Sidebar.TButton", background='#181818', borderwidth=0)
    style.map("Sidebar.TButton", background=[('active', '#2c2c2c')])

    style.configure("Main.TFrame", background='#2c2c2c')
    style.configure("Main.TLabel", background='#2c2c2c', foreground="orange", font=("Arial", 24, "bold"))
    
def resource_path(relative_path):
    """ Get the absolute path to a resource bundled with PyInstaller """
    try:
        # PyInstaller creates a temporary folder and stores the resources there
        base_path = sys._MEIPASS
    except Exception:
        # If running normally, use the current directory
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def navigate_to_root(main_frame):
    for widget in main_frame.winfo_children():
        widget.destroy()

    root_window_label = ttk.Label(main_frame, text="NetWire v1.0.2", style="Main.TLabel")
    root_window_label.pack(pady=50)

    github_link_label = tk.Label(main_frame, text="https://github.com/pipohappy/networkapp55.git", font=("Arial", 18, "bold"), bg='#2c2c2c', fg="orange", cursor="hand2")
    github_link_label.pack(pady=20)
    
    github_link_label.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/pipohappy/networkapp55.git"))

    guidance_image = Image.open(resource_path("assets/guidance.png"))
    guidance_icon = ImageTk.PhotoImage(guidance_image)
    
    question_button = tk.Button(main_frame, image=guidance_icon, bg='#2c2c2c', relief='ridge', highlightbackground='white', activebackground='#181818', bd=2, command=lambda: print("Help button clicked"))
    question_button.image = guidance_icon  # Keep a reference to the image
    question_button.place(relx=1.0, rely=0.0, anchor="ne", x=-25, y=5)

def main():
    global root, main_frame
    root = ThemedTk(theme="equilux")
    root.attributes("-fullscreen", True)
    root.configure(bg='#181818')

    style = ttk.Style()
    create_styles(style)

    # Load images for the buttons using resource_path()
    devices_icon = tk.PhotoImage(file=resource_path("assets/Multiple_devices.png"))
    traffic_icon = tk.PhotoImage(file=resource_path("assets/Data_transfer.png"))
    intconsole_icon = tk.PhotoImage(file=resource_path("assets/Console.png"))

    # Load and resize the image
    fs_image = Image.open(resource_path("assets/sff.png"))
    fs_image = fs_image.resize((37, 24))
    fs_icon = ImageTk.PhotoImage(fs_image)

    # Create the header frame
    header_frame = ttk.Frame(root, style="Header.TFrame")
    header_frame.pack(fill="x")

    applabel = ttk.Button(header_frame, text="NetWire", style="NetWire.TButton", command=lambda: navigate_to_root(main_frame), width=7)
    applabel.pack(side="left")

    close_button = ttk.Button(header_frame, text="X", style="Header.TButton", command=root.destroy, width=3)
    close_button.pack(side="right")

    toggle_fs_button = ttk.Button(header_frame, image=fs_icon, style="Header.TButton", command=lambda: toggle_full_screen(root))
    toggle_fs_button.pack(side="right")

    minimize_button = ttk.Button(header_frame, text="_", style="Header.TButton", command=root.iconify, width=3)
    minimize_button.pack(side="right")

    # Create the sidebar frame
    sidebar_frame = ttk.Frame(root, style="Sidebar.TFrame")
    sidebar_frame.pack(side="left", fill="y")

    # Create the main frame
    main_frame = ttk.Frame(root, style="Main.TFrame")
    main_frame.pack(fill="both", expand=True)

    # Default view when app starts
    navigate_to_root(main_frame)

    # Define the stop_scanning function (this is an example, modify it as per your requirements)
    def stop_scanning():
        print("Scanning stopped.")  # Example action, modify this as necessary

    # Add buttons for navigation
    button1 = ttk.Button(sidebar_frame, image=devices_icon, style="Sidebar.TButton", command=lambda: navigate_to_devices(main_frame))
    button1.pack(fill="x", pady=10, padx=20)

    button2 = ttk.Button(sidebar_frame, image=traffic_icon, style="Sidebar.TButton", command=lambda: navigate_to_traffic(main_frame, stop_scanning))  # Pass stop_scanning here
    button2.pack(fill="x", pady=10, padx=20)

    button3 = ttk.Button(sidebar_frame, image=intconsole_icon, style="Sidebar.TButton", command=lambda: navigate_to_console(main_frame, stop_scanning))  # Pass stop_scanning here
    button3.pack(fill="x", pady=10, padx=20)

    def toggle_full_screen(root):
        if root.attributes("-fullscreen"):
            root.attributes("-fullscreen", False)
        else:
            root.attributes("-fullscreen", True)

    root.mainloop()

if __name__ == "__main__":
    main()

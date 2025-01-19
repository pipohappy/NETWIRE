import speedtest
import threading
from speedtest import ConfigRetrievalError

# Global variables
animation_running = False

def run_speed_test_thread(loading_label, result_text):
    global animation_running
    animation_running = True
    loading_label.config(text="Measuring speed, please wait...")
    loading_label.after(100, lambda: animate_loading(loading_label))  # Start the loading animation
    thread = threading.Thread(target=run_speed_test, args=(loading_label, result_text))
    thread.start()

def animate_loading(loading_label):
    if animation_running:
        current_text = loading_label.cget("text")
        if current_text.endswith("..."):
            loading_label.config(text="Measuring speed, please wait")
        else:
            loading_label.config(text=current_text + ".")
        loading_label.after(500, lambda: animate_loading(loading_label))  # Update every 500 ms

def run_speed_test(loading_label, result_text):
    global animation_running
    try:
        st = speedtest.Speedtest()
        # Get the best server
        st.get_best_server()

        # Perform the speed test
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping = st.results.ping
        isp = st.results.client['isp']  # Get ISP information

        # Update the result text box with the results safely
        def update_text():
            if result_text.winfo_exists():  # Check if the text widget still exists
                result_text.config(state="normal")  # Enable editing
                result_text.delete(1.0, "end")  # Clear previous results
                result_text.insert(
                    "end",
                    f"Download Speed: {download_speed:.2f} Mbps\n"
                    f"Upload Speed: {upload_speed:.2f} Mbps\n"
                    f"Ping: {ping} ms\n"
                    f"ISP: {isp}"
                )
                result_text.config(state="disabled")  # Disable editing
            if loading_label.winfo_exists():  # Check if the loading label still exists
                loading_label.config(text="")  # Stop the loading animation

        # Schedule the update on the main thread
        loading_label.after(0, update_text)

    except ConfigRetrievalError as e:
        print(f"Failed to retrieve speed test configuration: {e}")
        def update_error():
            if result_text.winfo_exists():
                result_text.config(state="normal")
                result_text.delete(1.0, "end")
                result_text.insert("end", "Speed test failed: Could not retrieve configuration.")
                result_text.config(state="disabled")
            if loading_label.winfo_exists():
                loading_label.config(text="")
        loading_label.after(0, update_error)

    except Exception as e:
        print(f"Speed test failed: {e}")
        def update_error():
            if result_text.winfo_exists():
                result_text.config(state="normal")
                result_text.delete(1.0, "end")
                result_text.insert("end", f"Speed test failed: {e}")
                result_text.config(state="disabled")
            if loading_label.winfo_exists():
                loading_label.config(text="")
        loading_label.after(0, update_error)

    # Stop the loading animation
    animation_running = False

def start_speed_test(loading_label, result_text):
    run_speed_test_thread(loading_label, result_text)

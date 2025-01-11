import speedtest
import threading
from speedtest import ConfigRetrievalError

# Global variables
animation_running = False

def run_speed_test_thread(loading_label, result_label):
    global animation_running
    animation_running = True
    loading_label.config(text="Measuring speed, please wait...")
    loading_label.after(100, lambda: animate_loading(loading_label))  # Start the loading animation
    thread = threading.Thread(target=run_speed_test, args=(loading_label, result_label))
    thread.start()

def animate_loading(loading_label):
    if animation_running:
        current_text = loading_label.cget("text")
        if current_text.endswith("..."):
            loading_label.config(text="Measuring speed, please wait")
        else:
            loading_label.config(text=current_text + ".")
        loading_label.after(500, lambda: animate_loading(loading_label))  # Update every 500 ms

def run_speed_test(loading_label, result_label):
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

        # Update the result label with the results safely
        def update_labels():
            if result_label.winfo_exists():  # Check if the label still exists
                result_label.config(text=f"Download Speed: {download_speed:.2f} Mbps\n"
                                        f"Upload Speed: {upload_speed:.2f} Mbps\n"
                                        f"Ping: {ping} ms\n"
                                        f"ISP: {isp}")
            if loading_label.winfo_exists():  # Check if the loading label still exists
                loading_label.config(text="")  # Stop the loading animation

        # Schedule the update on the main thread
        loading_label.after(0, update_labels)

    except ConfigRetrievalError as e:
        print(f"Failed to retrieve speed test configuration: {e}")
        def update_error():
            if result_label.winfo_exists():
                result_label.config(text="Speed test failed: Could not retrieve configuration.")
            if loading_label.winfo_exists():
                loading_label.config(text="")
        loading_label.after(0, update_error)

    except Exception as e:
        print(f"Speed test failed: {e}")
        def update_error():
            if result_label.winfo_exists():
                result_label.config(text=f"Speed test failed: {e}")
            if loading_label.winfo_exists():
                loading_label.config(text="")
        loading_label.after(0, update_error)

    # Stop the loading animation
    animation_running = False

def start_speed_test(loading_label, result_label):
    run_speed_test_thread(loading_label, result_label)
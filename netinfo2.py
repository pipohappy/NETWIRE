import subprocess

def nmap_scan(ip):
    try:
        # Run the nmap command and capture the output
        nmap_result = subprocess.run(['nmap', '-sV', ip], capture_output=True, text=True)
        return nmap_result.stdout
    except Exception as e:
        return f"Error running Nmap: {str(e)}"
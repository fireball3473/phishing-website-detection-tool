import requests
import sys
import time
import threading

# Global control variable
stop_spinner = False

def spinning_cursor(task_name):
    chars = ['|', '/', '-', '\\']
    while not stop_spinner:
        for char in chars:
            if stop_spinner: break
            sys.stdout.write(f"\r{task_name}... {char}")
            sys.stdout.flush()
            time.sleep(0.1)

def get_usom_blacklist(limit=100):
    global stop_spinner
    try:
        url = "https://www.usom.gov.tr/url-list.txt"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        # --- START SPINNER ---
        stop_spinner = False
        spinner = threading.Thread(target=spinning_cursor, args=("Retrieving USOM data",))
        spinner.start()

        # Data retrieval process from the internet (Timeout period 60 seconds)
        response = requests.get(url, headers=headers, timeout=60, verify=True)
        
        # --- STOP SPINNER ---
        stop_spinner = True
        spinner.join()

        if response.status_code == 200:
            sys.stdout.write("\rUSOM data retrieved successfully!   \n")
            lines = [line.strip().lower() for line in response.text.split('\n') if line.strip()]
            latest_sites = set(lines[:limit]) 
            print(f"USOM List Ready: The first {len(latest_sites)} address has been loaded.")
            return latest_sites
        else:
            sys.stdout.write(f"\rUSOM Server Error: {response.status_code}\n")
            return set()
            
    except requests.exceptions.Timeout:
        stop_spinner = True
        print("\rTIMED OUT: USOM server is too slow.")
        return set()
    except Exception as e:
        stop_spinner = True
        print(f"\rAn unexpected error occurred: {e}")
        return set()
import pandas as pd
import numpy as np
import math
import os
import sys
import time
import threading
from urllib.parse import urlparse

# Global control variable
stop_spinner = False

# Spinning Cursor Function
def spinning_cursor():
    chars = ['|', '/', '-', '\\']
    while not stop_spinner:
        for char in chars:
            if stop_spinner: break
            sys.stdout.write(f"\rFeatures are calculating... {char}")
            sys.stdout.flush()
            time.sleep(0.1)

def calculate_entropy(text):
    text = str(text)
    if not text or text == 'nan': return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def enrich():
    global stop_spinner
    input_path = './datasets/dataset_full.csv'
    output_path = './datasets/dataset_v2.csv'

    print(f"Checking: {input_path}")
    
    if not os.path.exists(input_path):
        print(f"ERROR: {input_path} file could not be found!")
        return

    try:
        print("Reading data set...")
        df = pd.read_csv(input_path)
        print(f"{len(df)} rows of data loaded.")

        # --- START SPINNER FOR PROGRESS ---
        stop_spinner = False
        spinner_thread = threading.Thread(target=spinning_cursor)
        spinner_thread.start()

        # --- CALCULATE NEW FEATURES (Original Logic) ---
        
        # 1. Entropy
        df['EntropyScore'] = df['URL'].apply(lambda x: calculate_entropy(urlparse(str(x)).hostname))
        
        # 2. New Dash
        df['NumDashURL'] = df['URL'].apply(lambda x: str(x).count('-'))
        
        # 3. Sensitive Words
        sensitive_words = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'wallet', 'binance', 'confirm']
        df['NoOfSensitiveWords'] = df['URL'].apply(lambda x: sum(1 for word in sensitive_words if word in str(x).lower()))
        
        # 4. Suspicious TLD
        suspicious_tlds = ['.cyou', '.info', '.top', '.xyz', '.online', '.site', '.click', '.pw']
        df['TldType'] = df['URL'].apply(lambda x: 1 if any(str(x).lower().endswith(t) for t in suspicious_tlds) else 0)

        # 5. Brand in Subdomain
        df['BrandInSubdomain'] = df['URL'].apply(lambda x: 1 if urlparse(str(x)).hostname and any(word in urlparse(str(x)).hostname.split('.')[0] for word in sensitive_words) else 0)

        # 6. URL Shortener
        shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyURL.com']
        df['ShortenedURL'] = df['URL'].apply(lambda x: 1 if any(s in str(x) for s in shorteners) else 0)

        # 7. Abnormal Domain
        df['AbnormalDomain'] = df['URL'].apply(lambda x: 1 if pd.Series(str(x)).str.contains(r'\.(com|net|org|gov|edu|com\.tr)\.').any() else 0)

        # --- STOP SPINNER ---
        stop_spinner = True
        spinner_thread.join()
        sys.stdout.write("\rFeatures calculated successfully!   \n")

        print("Saving new file...")
        df.to_csv(output_path, index=False)
        
        if os.path.exists(output_path):
            print(f"‘{output_path}’ has been created successfully.")
        else:
            print("The file has been created successfully, but it cannot be found.")

    except Exception as e:
        stop_spinner = True # Stop spinner if there is an error
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    enrich()
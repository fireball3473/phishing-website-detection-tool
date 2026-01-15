import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
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

# Must be EXACTLY the same as the column names in the CSV
FEATURE_NAMES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
    'LetterRatioInURL', 'DegitRatioInURL', 'NoOfOtherSpecialCharsInURL', 'IsHTTPS',
    'LineOfCode', 'HasPasswordField', 'HasHiddenFields', 'NoOfImage', 'NoOfCSS', 
    'NoOfJS', 'NoOfExternalRef'
]

# --- STEP 1: UPLOAD THE DATASET ---
print("[Step 1] Initializing data load...")
stop_spinner = False
spinner = threading.Thread(target=spinning_cursor, args=("Dataset is loading",))
spinner.start()

try:
    df = pd.read_csv('./datasets/dataset_full.csv')
    df.columns = df.columns.str.strip()
    
    X = df[FEATURE_NAMES]
    y = df['label']
    
    # Stop and clean the spinner
    stop_spinner = True
    spinner.join()
    sys.stdout.write("\rDataset loaded successfully!      \n")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # --- STEP 2: MODEL TRAINING ---
    print("[Step 2] Starting model training...")
    stop_spinner = False
    spinner = threading.Thread(target=spinning_cursor, args=("The model is training",))
    spinner.start()

    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # Stop and clean the spinner
    stop_spinner = True
    spinner.join()
    sys.stdout.write("\r✅ Model training completed!         \n")

    # --- STEP 3: SAVING ---
    joblib.dump(model, 'phishing_model.joblib')
    print("The model has been successfully saved as 'phishing_model.joblib'.")

except Exception as e:
    stop_spinner = True
    print(f"\nAn unexpected error occurred: {e}")
from flask import Flask, request, jsonify
from flask_cors import CORS 
import joblib 
import numpy as np
import pandas as pd
import os
import traceback
from urllib.parse import urlparse
from apscheduler.schedulers.background import BackgroundScheduler

from trust_list import tranco_checker
from whois_age_service import get_domain_age_days
from usom_service import get_usom_blacklist

# --- 1. GLOBAL BLACKLIST UPLOAD ---
def load_blacklist():
    blacklist = set()
    file_path = './datasets/phishing_domains_list.lst' 
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    clean_line = line.strip().lower()
                    if clean_line and not clean_line.startswith('#'):
                        blacklist.add(clean_line)
            print(f"{len(blacklist)} domain loaded successfully.")
    except Exception as e:
        print(f"Error loading blacklist: {e}")
    return blacklist

GLOBAL_BLACKLIST = load_blacklist()
USOM_LIST = get_usom_blacklist()

# --- 2. SCHEDULER SYSTEM ---
def update_usom_task():
    global USOM_LIST
    new_usom = get_usom_blacklist()
    if new_usom:
        USOM_LIST = new_usom
        print(f"--- [SCHEDULER] Fresh USOM Data Sync Success ---")

scheduler = BackgroundScheduler()
scheduler.add_job(func=update_usom_task, trigger="interval", seconds=600)
scheduler.start()

app = Flask(__name__)
CORS(app) 

# --- 3. MODEL LOADING ---
FEATURE_NAMES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
    'LetterRatioInURL', 'DegitRatioInURL', 'NoOfOtherSpecialCharsInURL', 'IsHTTPS',
    'LineOfCode', 'HasPasswordField', 'HasHiddenFields', 'NoOfImage', 'NoOfCSS', 
    'NoOfJS', 'NoOfExternalRef'
]

try:
    model = joblib.load('phishing_model.joblib')
    print("AI Engine Active.")
except Exception as e:
    model = None

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url_raw = data.get('url', '').lower().strip()
        if not url_raw: return jsonify({'error': 'URL missing'}), 400

        # --- 1. DOMAIN ANALYSIS ---
        parsed_url = urlparse(url_raw)
        netloc = parsed_url.netloc.split(':')[0].replace('www.', '').strip()
        if not netloc:
            netloc = url_raw.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0].replace('www.', '').strip()

        parts = netloc.split('.')
        main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else netloc

        # --- 2. EXCLUDE LIST (Free hosting websites) ---
        exclude_list = ['netlify.app', 'vercel.app', 'github.io', 'firebaseapp.com', 'pages.dev', 'web.app', 'herokuapp.com', 'my-homeip.com']
        is_excluded = any(netloc.endswith(ext) for ext in exclude_list)

        # --- 3. TRUSTED LIST CHECK (Whitelist) ---
        if not is_excluded and len(main_domain) > 3:
            if tranco_checker.is_trusted(main_domain) or tranco_checker.is_trusted(netloc):
                return jsonify({'isPhishing': False, 'confidence': 0.0, 'status': 'trusted_global', 'usom_detected': False, 'ai_score': 0.0})

        # --- 4. BLACKLIST CHECK (Deterministic Block) ---
        is_in_blacklist = netloc in GLOBAL_BLACKLIST or main_domain in GLOBAL_BLACKLIST
        usom_match = (netloc in USOM_LIST) if USOM_LIST else False
        if usom_match or is_in_blacklist:
            return jsonify({'isPhishing': True, 'confidence': 1.0, 'usom_detected': True, 'ai_score': 1.0, 'status': 'blacklisted'})

        # --- 5. AI ENGINE (AI SCORE - 40% Impact) ---
        features_dict = {f: data.get(f, 0) for f in FEATURE_NAMES}
        features_df = pd.DataFrame([features_dict])[FEATURE_NAMES]
        ai_score = float(model.predict_proba(features_df)[0][1]) if model else 0.5

        # --- 6. HEURISTIC SCORE (35% Impact) ---
        radar_keywords = ['a101', '101', 'sokmarket', 'e-devlet', 'edevlet', 'kampanya', 'hediye', 'giris', 'binance', 'wallet', 'bonus', 'kazan', 'fbclid', 'pixel']
        search_space = (url_raw + " " + data.get('pageTitle', '')).lower()
        
        radar_score = 0.0
        if any(w in search_space for w in radar_keywords):
            radar_score = 0.85 # If there is a suspicious word, the radar score is high.

        # --- 7. DOMAIN TRUST (TRUST SCORE - 25% Impact) ---
        domain_age = get_domain_age_days(main_domain)
        age_risk_factor = 0.5 # Neutral start
        
        if domain_age is not None:
            if domain_age < 30: age_risk_factor = 0.95    # Very new (High Risk)
            elif domain_age < 180: age_risk_factor = 0.75 # New
            elif domain_age > 1095: age_risk_factor = 0.10 # Old/Reliable (Low Risk)
            elif domain_age > 365: age_risk_factor = 0.35  # Reliable
        else:
            age_risk_factor = 0.80 # If there is no Whois, suspect

        # --- 8. HYBRID WEIGHTED CALCULATION ---
        # Formula: (AI * 0.40) + (Radar * 0.35) + (Age * 0.25)
        final_confidence = (ai_score * 0.40) + (radar_score * 0.35) + (age_risk_factor * 0.25)

        # Smart Boost: If both the radar is triggered and the domain is very new
        if radar_score > 0.8 and age_risk_factor > 0.7:
            final_confidence = min(final_confidence + 0.15, 1.0)

        is_phishing_detected = bool(final_confidence >= 0.50)
        
        print(f"Details for {netloc}: AI:{ai_score:.2f} | Radar:{radar_score:.2f} | AgeRisk:{age_risk_factor:.2f} | Final:{final_confidence:.2f}")

        return jsonify({

            'isPhishing': is_phishing_detected,
            'confidence': float(final_confidence),
            'usom_detected': bool(usom_match),
            'ai_score': float(ai_score)
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/report', methods=['POST'])
def report():
    try:
        data = request.json
        file_path = os.path.join('datasets', 'report_data.csv')
        if not os.path.exists('datasets'): os.makedirs('datasets')
        df = pd.DataFrame([{
            'url': data.get('url'),
            'user_label': data.get('isPhishing'),
            'model_confidence': data.get('confidence'),
            'timestamp': pd.Timestamp.now().isoformat()
        }])
        df.to_csv(file_path, mode='a', header=not os.path.exists(file_path), index=False)
        return jsonify({'message': 'Success'}), 200
    except:
        return jsonify({'message': 'Error'}), 500

if __name__ == '__main__':
    app.run(port=5000, debug=True, use_reloader=False)
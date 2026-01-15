from flask import Flask, request, jsonify
from flask_cors import CORS 
import joblib 
import numpy as np
import pandas as pd
import os

from trust_list import tranco_checker
from whois_age_service import get_domain_age_days
# from usom_service import get_usom_blacklist
from urllib.parse import urlparse

# API kurulumu
app = Flask(__name__)
CORS(app) 

# --- MODEL YÜKLEME VE ÖZELLİK LİSTESİ ---

# Veri setindeki (CSV) sütun isimleriyle BİREBİR AYNI SIRALAMA
FEATURE_NAMES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
    'LetterRatioInURL', 'DegitRatioInURL', 'NoOfOtherSpecialCharsInURL', 'IsHTTPS',
    'LineOfCode', 'HasPasswordField', 'HasHiddenFields', 'NoOfImage', 'NoOfCSS', 
    'NoOfJS', 'NoOfExternalRef'
]

try:
    # phishing_model.joblib dosyasını yüklüyoruz
    model = joblib.load('phishing_model.joblib')
    print(f"✅ Makine Öğrenimi Modeli ({len(FEATURE_NAMES)} özellikli) Başarıyla Yüklendi.")
except FileNotFoundError:
    print("❌ HATA: 'phishing_model.joblib' bulunamadı. Lütfen önce train_model.py'yi çalıştırın.")
    model = None
except Exception as e:
    print(f"❌ HATA: Model yüklenirken bir sorun oluştu: {e}")
    model = None

# USOM_LIST = get_usom_blacklist()

@app.route('/predict', methods=['POST'])
def predict():
    # 1. Değişkeni en başta tanımlayarak "not defined" hatasını önlüyoruz
    usom_detected = False
    final_confidence = 0.0
    
    try:
        data = request.get_json()
        url_raw = data.get('url', '').lower().strip()

        # --- USOM KONTROLÜ ---
        parsed_url = urlparse(url_raw)
        domain = parsed_url.netloc.replace('www.', '').split(':')[0].strip()
        if not domain:
            domain = url_raw.split('/')[0].replace('www.', '').strip()

            # --- 0. KONTROL: TRANCO TRUST LIST (Hızlı Tahliye) ---
        if tranco_checker.is_trusted(domain):
            print(f"🛡️ TRANCO GÜVENLİ SİTE: {domain}")
            return jsonify({
                'isPhishing': False,
                'confidence': 0.0,
                'usom_detected': False,
                'ai_score': 0.0,
                'status': 'trusted_global'
            })

#        if USOM_LIST:
            if domain in USOM_LIST:
                usom_detected = True
            if not usom_detected:
                for bad_url in USOM_LIST:
                    clean_bad_url = bad_url.strip().lower()
                    if clean_bad_url == domain or (len(clean_bad_url) > 4 and clean_bad_url in url_raw):
                        usom_detected = True
                        break

        # --- YAPAY ZEKA ANALİZİ ---
        features_dict = {
            'URLLength': data.get('URLLength', 0),
            'DomainLength': data.get('DomainLength', 0),
            'IsDomainIP': data.get('IsDomainIP', 0),
            'TLDLength': data.get('TLDLength', 0),
            'NoOfSubDomain': data.get('NoOfSubDomain', 0),
            'LetterRatioInURL': data.get('LetterRatioInURL', 0),
            'DegitRatioInURL': data.get('DegitRatioInURL', 0),
            'NoOfOtherSpecialCharsInURL': data.get('NoOfOtherSpecialCharsInURL', 0),
            'IsHTTPS': data.get('IsHTTPS', 0),
            'LineOfCode': data.get('LineOfCode', 0),
            'HasPasswordField': data.get('HasPasswordField', 0),
            'HasHiddenFields': data.get('HasHiddenFields', 0),
            'NoOfImage': data.get('NoOfImage', 0),
            'NoOfCSS': data.get('NoOfCSS', 0),
            'NoOfJS': data.get('NoOfJS', 0),
            'NoOfExternalRef': data.get('NoOfExternalRef', 0)
        }
        
        # Sütun isimleri uyarısını çözmek için veriyi DataFrame'e çeviriyoruz
        features_df = pd.DataFrame([features_dict])
        
        probability = model.predict_proba(features_df)[0][1] if model else 0.5

        # --- AKILLI CEZA PUANI ---
        if probability > 0.40:
            danger_keywords = ['a101', 'sokmarket', 'e-devlet', 'edevlet', 'kampanya', 'hediye', 'giris']
            if any(kw in url_raw for kw in danger_keywords):
                probability += 0.30
            if data.get('HasPasswordField') == 1:
                probability += 0.20
        
        # --- 4. DOMAİN YAŞI KONTROLÜ (Çarpanlı Güven Sistemi) ---
        domain_age = get_domain_age_days(domain)
        trust_multiplier = 1.0 # Başlangıç çarpanı (etkisiz)
        
        if domain_age is not None:
            print(f"📅 Domain Yaşı: {domain_age} gün")
            
            if domain_age < 30: 
                # Çok yeni site: Riski %60 artır (Örn: 0.50 -> 0.80 olur)
                trust_multiplier = 1.60
                print("⚠️ ÇOK YENİ DOMAİN: Risk x1.6 katına çıkarıldı.")
                
            elif domain_age < 180: 
                # Yeni site: Riski %30 artır (Örn: 0.50 -> 0.65 olur)
                trust_multiplier = 1.30
                print("⚠️ YENİ DOMAİN: Risk x1.3 katına çıkarıldı.")
                
            elif domain_age > 1095: # 3 Yıldan eski
                # Köklü site: Riski %60 AZALT (Örn: 0.40 -> 0.16 olur)
                # Profesyonel sistemlerde 3+ yıl "altın standart"tır.
                trust_multiplier = 0.40
                print("✅ KÖKLÜ DOMAİN (3+ Yıl): Risk %60 oranında düşürüldü (x0.40).")
                
            elif domain_age > 365: # 1 Yıldan eski
                # Güvenilir site: Riski %30 AZALT (Örn: 0.40 -> 0.28 olur)
                trust_multiplier = 0.70
                print("✅ GÜVENİLİR DOMAİN (1+ Yıl): Risk %30 oranında düşürüldü (x0.70).")
        else:
            # Whois bilgisi gizliyse riski hafifçe artır
            trust_multiplier = 1.15
            print("ℹ️ WHOIS BİLGİSİ YOK: Risk x1.15 çarpanı uygulandı.")

        # --- 5. HARMANLAMA VE FINAL HESAPLAMA ---
        if usom_detected:
            final_confidence = 1.0
            print(f"🚨 USOM YAKALANDI: {domain}")
        else:
            # AI olasılığını güven çarpanı ile ölçeklendiriyoruz
            calculated_risk = probability * trust_multiplier
            # Sınırları 0.0 ile 1.0 arasında tutuyoruz
            final_confidence = min(max(calculated_risk, 0.0), 1.0)

        print(f"Final Risk Analizi: {url_raw[:40]}... | Ham AI: {probability:.2f} | Çarpan: {trust_multiplier} | Sonuç: {final_confidence:.2f}")

        # Karar Eşiği (Threshold): 0.50 idealdir
        is_phishing_detected = bool(final_confidence >= 0.50)

        print(f"Analiz: {url_raw[:50]}... | USOM: {usom_detected} | Risk: {final_confidence:.2f}")

        return jsonify({
            'isPhishing': is_phishing_detected,
            'confidence': float(final_confidence),
            'usom_detected': usom_detected,
            'ai_score': float(probability)
        })

    except Exception as e:
        # Hata ayıklama için hatanın yerini yazdırır
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 400

@app.route('/report', methods=['POST'])
def report():
    try:
        data = request.json
        url = data.get('url')
        user_label = data.get('isPhishing')
        model_confidence = data.get('confidence')
        
        if not url or user_label is None:
            return jsonify({'message': 'Eksik veri.'}), 400

        target_folder = 'datasets'
        file_path = os.path.join(target_folder, 'report_data.csv')

        if not os.path.exists(target_folder):
            os.makedirs(target_folder)

        report_data = {
            'url': url,
            'user_label': user_label,
            'model_confidence': model_confidence,
            'timestamp': pd.Timestamp.now().isoformat()
        }

        df = pd.DataFrame([report_data])
        file_exists = os.path.isfile(file_path)
        df.to_csv(file_path, mode='a', header=not file_exists, index=False)

        return jsonify({'message': 'Geri bildirim datasets klasörüne kaydedildi.'}), 200

    except Exception as e:
        print(f"Rapor hatası: {e}")
        return jsonify({'message': 'Sunucu hatası.'}), 500

if __name__ == '__main__':
    # Localhost üzerinde 5000 portunda çalıştır
    print("API http://127.0.0.1:5000/predict adresinde dinlemede...")
    app.run(port=5000, debug=True)
# train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# CSV'deki sütun isimleriyle BİREBİR AYNI olmalı
FEATURE_NAMES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'TLDLength', 'NoOfSubDomain',
    'LetterRatioInURL', 'DegitRatioInURL', 'NoOfOtherSpecialCharsInURL', 'IsHTTPS',
    'LineOfCode', 'HasPasswordField', 'HasHiddenFields', 'NoOfImage', 'NoOfCSS', 
    'NoOfJS', 'NoOfExternalRef'
]

print("[Adım 1] Veri seti yükleniyor...")
df = pd.read_csv('./datasets/dataset_full.csv')
df.columns = df.columns.str.strip() # Sütun isimlerindeki gizli boşlukları temizler

X = df[FEATURE_NAMES]
y = df['label'] # CSV'ndeki hedef sütun adı 'label'

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("[Adım 2] Model eğitiliyor...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

joblib.dump(model, 'phishing_model.joblib')
print("✅ Model 'phishing_model.joblib' olarak başarıyla kaydedildi.")
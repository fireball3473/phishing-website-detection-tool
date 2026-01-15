const translations = {
    en: {
        brand: "Phishing Detector",
        status_active: "Protection is Enabled",
        status_offline: "Protection is Disabled",
        analyzing: "Analyzing...",
        safe_domain: "GLOBAL TRUSTED SITE",
        safe_desc: "This website is on the Global Trusted List.",
        danger_detected: "PHISHING DETECTED",
        scam_identified: "USOM BLACKLIST DETECTED",
        usom_desc: "This domain is listed as harmful by official authorities.",
        risk_score: "Risk Score",
        report_safe: "Report as Safe",
        report_danger: "Report as Unsafe",
        footer: "Page security is analyzed by artificial intelligence and other systems.",
        protected_page: "BROWSER-PROTECTED PAGE",
        protected_desc: "This page is protected by your browser.",
        suspicious: "WARNING: Suspicious page.",
        unsafe_msg: "WARNING: Page is unsafe.",
        secure_msg: "This page appears to be secure.",
        reporting: "Sending report...",
        report_thanks: "Report sent. Thank you!",
        report_error: "Connection error!"
    },
    tr: {
        brand: "Oltalama Dedektörü",
        status_active: "Koruma Aktif",
        status_offline: "Koruma Devre Dışı",
        analyzing: "Analiz ediliyor...",
        safe_domain: "GÜVENLİ KÜRESEL SİTE",
        safe_desc: "Bu web sitesi Küresel Güven Listesindedir.",
        danger_detected: "OLTALAMA TESPİT EDİLDİ",
        scam_identified: "USOM KARA LİSTE TESPİT EDİLDİ",
        usom_desc: "Bu adres resmi makamlarca zararlı olarak listelenmiştir.",
        risk_score: "Risk Skoru",
        report_safe: "Güvenli Olarak Bildir",
        report_danger: "Güvensiz Olarak Bildir",
        footer: "Sayfa güvenliği yapay zeka ve diğer sistemler tarafından analiz edilir.",
        protected_page: "TARAYICI KORUMALI SAYFA",
        protected_desc: "Bu sayfa tarayıcınız tarafından korunuyor. Analiz edilemez.",
        suspicious: "UYARI: Şüpheli sayfa.",
        unsafe_msg: "UYARI: Sayfa güvensiz.",
        secure_msg: "Bu sayfa güvenli görünüyor.",
        reporting: "Rapor gönderiliyor...",
        report_thanks: "Rapor iletildi. Teşekkürler!",
        report_error: "Bağlantı hatası!"
    }
};

let currentLang = 'en';
let currentUrl = '';
let currentConfidence = 0.0;
const REPORT_API_URL = 'http://localhost:5000/report';

// --- 1. REPORTING FUNCTION ---
function sendReport(userIsPhishing) {
    const reportDiv = document.getElementById('report-buttons');
    const t = translations[currentLang];
    
    const originalContent = reportDiv.innerHTML;
    reportDiv.innerHTML = `<div style="text-align:center; padding:10px; font-size:12px; color:gray;">${t.reporting}</div>`;

    const reportData = {
        url: currentUrl,
        isPhishing: userIsPhishing,
        confidence: currentConfidence
    };

    fetch(REPORT_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(reportData)
    })
    .then(response => {
        if (response.ok) {
            reportDiv.innerHTML = `
                <div style="background: rgba(16, 185, 129, 0.1); color: #059669; padding: 10px; border-radius: 8px; text-align: center; font-size: 12px; font-weight: bold; border: 1px solid #059669;">
                    ✓ ${t.report_thanks}
                </div>`;
        } else {
            throw new Error();
        }
    })
    .catch(() => {
        reportDiv.innerHTML = `<div style="color: #dc2626; text-align: center; font-size: 12px;">${t.report_error}</div>`;
        setTimeout(() => { reportDiv.innerHTML = originalContent; attachButtonEvents(); }, 2000);
    });
}

function attachButtonEvents() {
    const safeBtn = document.getElementById('report-safe');
    const phishBtn = document.getElementById('report-phishing');
    if (safeBtn) safeBtn.onclick = () => sendReport(false);
    if (phishBtn) phishBtn.onclick = () => sendReport(true);
}

function applyLanguage(lang) {
    currentLang = lang;
    const t = translations[lang];
    document.querySelector('h3').textContent = t.brand;
    document.querySelector('.footer-text').textContent = t.footer;
    document.getElementById('report-safe').textContent = t.report_safe;
    document.getElementById('report-phishing').textContent = t.report_danger;
    
    chrome.storage.local.get(['extensionEnabled'], (result) => {
        const isEnabled = result.extensionEnabled !== false;
        document.getElementById('switch-label').textContent = isEnabled ? t.status_active : t.status_offline;
    });
}

// --- REFRESH THE PAGE WHEN THE LANGUAGE CHANGES ---
document.getElementById('lang-select').addEventListener('change', (e) => {
    const selectedLang = e.target.value;
    chrome.storage.local.set({ language: selectedLang }, () => {
        applyLanguage(selectedLang);
        
        // Find the active tab and refresh it
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs[0]) {
                chrome.tabs.reload(tabs[0].id);
            }
        });

        updateStatus(); 
    });
});

function updateStatus() {
    const statusElement = document.getElementById('status');
    const reportDiv = document.getElementById('report-buttons');
    const t = translations[currentLang];

    chrome.storage.local.get(['extensionEnabled'], (result) => {
        const isEnabled = result.extensionEnabled !== false; 
        
        if (!isEnabled) {
            statusElement.textContent = t.status_offline;
            statusElement.style.color = "gray";
            document.body.classList.remove('theme-safe', 'theme-warn', 'theme-danger');
            if (reportDiv) reportDiv.style.display = 'none';
            return;
        }

        statusElement.textContent = t.analyzing;
        statusElement.style.color = 'gray';

        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs[0] && tabs[0].id) {
                currentUrl = tabs[0].url; 
                chrome.runtime.sendMessage({ 
                    action: "analyzeCurrentTab", 
                    tabId: tabs[0].id, 
                    url: tabs[0].url
                });
            }
        });
    });
}

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === "updatePopupStatus") {
        const statusElement = document.getElementById('status');
        const reportDiv = document.getElementById('report-buttons');
        const t = translations[currentLang];
        const body = document.body;

        if (request.result.status === 'error') {
            statusElement.innerHTML = `<div style="color: #dc2626; font-weight: bold;">${t.report_error}</div>`;
            document.body.classList.remove('theme-safe', 'theme-warn', 'theme-danger');
            return; // Don't show the analysis results
        }

        // Clear themes on every new message
        body.classList.remove('theme-safe', 'theme-warn', 'theme-danger');

        // 1. STATUS: BROWSER-PROTECTED PAGES (chrome://, settings, etc.)
        if (request.result.status === 'browser_protected') {
            statusElement.innerHTML = `<div style="color: #64748b;">${t.protected_page}</div>`;
            if (reportDiv) reportDiv.style.display = 'none';
            return; // Stop analysis
        }

        // 2. SITUATION: GLOBAL TRUST LIST (TRANCO - google.com, etc.)
        // When this block runs, the buttons close and you never proceed to the next lines (AI analysis).
        if (request.result.status === 'trusted_global' || request.result.isWhitelisted) {
            body.classList.add('theme-safe');
            statusElement.innerHTML = `
                <div style="color: #059669; font-weight: 800; font-size: 15px;">${t.safe_domain}</div>
                <div style="font-size: 11px; font-weight: 400; color: #10b981; margin-top: 4px;">${t.safe_desc}</div>
            `;
            if (reportDiv) reportDiv.style.display = 'none'; // Remove all buttons
            return; // VERY CRITICAL: Stop the function here, do not proceed further!
        }

        // --- BELOW THIS POINT IS ONLY FOR SITES NOT ON THE TRUSTED LIST (REQUIRING ANALYSIS) ---

        currentConfidence = request.result.confidence; 
        const isUsom = request.result.usom_detected; 
        const riskPercent = (currentConfidence * 100).toFixed(2);
        
        if (isUsom) {
            body.classList.add('theme-danger');
            statusElement.innerHTML = `
                <div style="color: #dc2626; margin-bottom: 4px; font-weight: 800;">${t.danger_detected}</div>
                <div style="font-size: 11px; font-weight: 500; color: #b91c1c;">${t.scam_identified}</div>
                <div style="font-size: 10px; font-weight: 400; color: #ef4444; margin-top: 4px;">${t.usom_desc}</div>
            `;
        } else {
            // ARTIFICIAL INTELLIGENCE SCORING LOGIC
            if (currentConfidence >= 0.66) {
                body.classList.add('theme-danger');
                statusElement.innerHTML = `<span style="color: #dc2626; font-weight: 700;">${t.unsafe_msg}</span><br><small style="font-weight:500;">${t.risk_score}: %${riskPercent}</small>`;
            } else if (currentConfidence >= 0.33) {
                body.classList.add('theme-warn');
                statusElement.innerHTML = `<span style="color: #d97706; font-weight: 700;">${t.suspicious}</span><br><small style="font-weight:500;">${t.risk_score}: %${riskPercent}</small>`;
            } else {
                body.classList.add('theme-safe');
                statusElement.innerHTML = `<span style="color: #059669; font-weight: 700;">${t.secure_msg}</span><br><small style="font-weight:500;">${t.risk_score}: %${riskPercent}</small>`;
            }
        }

        // Show buttons only on analyzed (non-listed) sites
        if (reportDiv) {
            reportDiv.style.display = 'block';
            attachButtonEvents();
        }
    }
});

document.addEventListener('DOMContentLoaded', function() {
    chrome.storage.local.get(['language'], (result) => {
        const lang = result.language || 'en';
        document.getElementById('lang-select').value = lang;
        applyLanguage(lang);
        updateStatus();
    });

    const enableSwitch = document.getElementById('enable-extension');
    if (enableSwitch) {
        chrome.storage.local.get(['extensionEnabled'], (result) => {
            enableSwitch.checked = result.extensionEnabled !== false;
        });

        enableSwitch.addEventListener('change', () => {
            const isEnabled = enableSwitch.checked;
            chrome.storage.local.set({ extensionEnabled: isEnabled }, () => {
                applyLanguage(currentLang);
                chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
                    if (tabs[0]) chrome.tabs.reload(tabs[0].id);
                });
                updateStatus();
            });
        });
    }
    attachButtonEvents();
});
// 1. Checking messages coming from the background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getPageContentFeatures") {
        const features = {
            LineOfCode: document.documentElement.innerHTML.length / 50,
            HasPasswordField: (
                document.querySelectorAll('input[type="password"]').length > 0 ||
                document.querySelectorAll('input[type="text"]').length > 0 ||
                document.querySelectorAll('input[type="tel"]').length > 0
            ) ? 1 : 0,
            HasHiddenFields: document.querySelectorAll('input[type="hidden"]').length > 0 ? 1 : 0,
            NoOfImage: document.images.length,
            NoOfCSS: document.querySelectorAll('link[rel="stylesheet"]').length,
            NoOfJS: document.scripts.length,
            NoOfExternalRef: Array.from(document.links).filter(link => !link.href.includes(window.location.hostname)).length
        };
        sendResponse(features);
    }

    if (request.action === "showWarning") {
        if (!document.getElementById('phishing-warning-modal')) {
            createWarningModal(request.riskPercent, request.usomDetected);
        }
    }
    return true;
});

// 2. Creating a Warning Modal (with Dynamic Button Text)
function createWarningModal(riskPercent, usomDetected) {
    const i18n = {
        en: {
            usom_title: 'SCAM WEBSITE DETECTED',
            usom_msg: `This site has been added to the fraud list by <b>USOM</b>. Do not enter any data under any circumstances.`,
            ai_high_title: 'CRITICAL RISK DETECTED!',
            ai_low_title: 'SUSPICIOUS PAGE',
            ai_msg: `This page has been analyzed by <b>Artificial Intelligence</b> and suspected of phishing.`,
            prob: "Phishing Probability",
            incorrect: "Is this detection incorrect? Report us.",
            safe: "Safe",
            unsafe: "Unsafe",
            leave: "CLOSE THIS PAGE",
            ignore_low: "Continue",
            ignore_high: "Continue (NOT RECOMMENDED!)",
            sending: "Sending...",
            success: "Received, thank you!",
            error: "Error!"
        },
        tr: {
            usom_title: 'DOLANDIRICI SİTE TESPİT EDİLDİ',
            usom_msg: `Bu site <b>USOM</b> tarafından dolandırıcılık listesine eklenmiştir. Hiçbir koşulda veri girişi yapmayın.`,
            ai_high_title: 'KRİTİK RİSK TESPİT EDİLDİ!',
            ai_low_title: 'ŞÜPHELİ SAYFA',
            ai_msg: `Bu sayfa <b>Yapay Zeka</b> tarafından analiz edilmiş ve oltalama şüphesi taşıdığı belirlenmiştir.`,
            prob: "Oltalama Olasılığı",
            incorrect: "Bu tespit hatalı mı? Bize bildirin.",
            safe: "Güvenli",
            unsafe: "Güvensiz",
            leave: "SAYFAYI KAPAT",
            ignore_low: "Devam Et",
            ignore_high: "Devam Et (ÖNERİLMEZ!)",
            sending: "İletiliyor...",
            success: "Alındı, teşekkürler!",
            error: "Hata!"
        }
    };

    chrome.storage.local.get(['language'], (res) => {
        const lang = res.language || 'en';
        const t = i18n[lang];

        // --- STATUS CHECK ---
        const isCritical = usomDetected || riskPercent >= 66;
        const cardBgColor = isCritical ? "rgba(220, 38, 38, 0.98)" : "rgba(245, 158, 11, 0.98)";
        
        // If suspicious, just “Continue”; if fraudulent, “Continue (NOT RECOMMENDED!)”
        const ignoreBtnText = isCritical ? t.ignore_high : t.ignore_low;

        const modal = document.createElement('div');
        modal.id = 'phishing-warning-modal';
        
        modal.style.cssText = `
            position: fixed !important; top: 0 !important; left: 0 !important; 
            width: 100vw !important; height: 100vh !important;
            background-color: rgba(255, 255, 255, 0.01) !important;
            z-index: 2147483647 !important;
            display: flex !important; justify-content: center !important; 
            align-items: center !important; 
            backdrop-filter: blur(30px) !important;
            -webkit-backdrop-filter: blur(30px) !important;
            transition: opacity 0.6s ease, backdrop-filter 0.6s ease !important;
            animation: modalFadeIn 0.8s ease-out !important;
            font-family: 'Segoe UI', system-ui, sans-serif !important;
        `;

        const styleTag = document.createElement('style');
        styleTag.textContent = `
            @keyframes modalFadeIn { from { opacity: 0; backdrop-filter: blur(0px); } to { opacity: 1; backdrop-filter: blur(30px); } }
            @keyframes cardSlideIn { from { transform: translateY(40px) scale(0.9); opacity: 0; } to { transform: translateY(0) scale(1); opacity: 1; } }
            .modal-exit-active { opacity: 0 !important; backdrop-filter: blur(0px) !important; -webkit-backdrop-filter: blur(0px) !important; pointer-events: none !important; }
            .card-exit-active { transform: translateY(60px) scale(0.8) !important; opacity: 0 !important; }
        `;
        document.head.appendChild(styleTag);

        const content = document.createElement('div');
        content.id = 'warning-card-content';
        content.style.cssText = `
            background: ${cardBgColor} !important; 
            padding: 50px !important; border-radius: 40px !important; 
            max-width: 480px !important; text-align: center !important; 
            box-shadow: 0 50px 100px rgba(0, 0, 0, 0.5) !important;
            color: white !important;
            border: 1px solid rgba(255, 255, 255, 0.2) !important;
            animation: cardSlideIn 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
            transition: transform 0.5s ease, opacity 0.5s ease !important;
        `;

        const probabilityRow = !usomDetected ? 
            `<div style="font-weight: 900; margin-bottom: 25px; color: white; background: rgba(0,0,0,0.2); display: inline-block; padding: 6px 16px; border-radius: 50px; font-size: 14px; letter-spacing: 0.5px;">${t.prob.toUpperCase()}: %${riskPercent}</div>` : 
            `<div style="margin-bottom: 25px;"></div>`; 

        content.innerHTML = `
            <h1 style="color: white; margin: 0 0 15px 0; font-size: 32px; font-weight: 800; line-height: 1.1;">
                ${usomDetected ? t.usom_title : (riskPercent >= 66 ? t.ai_high_title : t.ai_low_title)}
            </h1>
            <p style="font-size: 17px; color: rgba(255,255,255,0.9); line-height: 1.6; margin-bottom: 35px; font-weight: 400;">
                ${usomDetected ? t.usom_msg : t.ai_msg}
            </p>
            
            ${probabilityRow}
            
            <button id="close-phishing-warning" style="width: 100%; background: #ffffff; color: ${isCritical ? '#dc2626' : '#b45309'}; border: none; padding: 22px; border-radius: 20px; cursor: pointer; font-weight: 800; font-size: 16px; margin-bottom: 15px; transition: 0.3s; box-shadow: 0 10px 25px rgba(0,0,0,0.15);">
                ${t.leave}
            </button>
            <button id="ignore-phishing-warning" style="background: transparent; color: rgba(255,255,255,0.7); border: none; cursor: pointer; text-decoration: underline; font-size: 14px; margin-bottom: 40px; font-weight: 500;">
                ${ignoreBtnText}
            </button>

            <div id="modal-report-section" style="border-top: 1px solid rgba(255,255,255,0.2); padding-top: 30px;">
                <p style="font-size: 13px; color: rgba(255,255,255,0.6); margin-bottom: 15px; font-weight: 500;">${t.incorrect}</p>
                <div style="display: flex; gap: 15px; justify-content: center;">
                    <button id="modal-report-safe" style="background: rgb(0, 255, 13); color: black; border: none; padding: 10px 22px; border-radius: 14px; cursor: pointer; font-size: 13px; font-weight: 700; transition: 0.2s;">${t.safe}</button>
                    <button id="modal-report-phishing" style="background: rgb(255, 0, 0); color: white; border: none; padding: 10px 22px; border-radius: 14px; cursor: pointer; font-size: 13px; font-weight: 700; transition: 0.2s;">${t.unsafe}</button>
                </div>
            </div>
        `;

        modal.appendChild(content);
        document.body.appendChild(modal);

        document.getElementById('modal-report-safe').onclick = () => sendModalReport(false, riskPercent, t);
        document.getElementById('modal-report-phishing').onclick = () => sendModalReport(true, riskPercent, t);
        document.getElementById('close-phishing-warning').onclick = () => chrome.runtime.sendMessage({ action: "closeTab" });
        
        document.getElementById('ignore-phishing-warning').onclick = () => {
            modal.classList.add('modal-exit-active');
            content.classList.add('card-exit-active');
            setTimeout(() => modal.remove(), 600);
        };
    });
}

function sendModalReport(userIsPhishing, riskPercent, t) {
    const reportSection = document.getElementById('modal-report-section');
    reportSection.innerHTML = `<p style="color: white; font-size: 14px; font-weight: bold;">${t.sending}</p>`;

    chrome.runtime.sendMessage({
        action: "reportFromModal",
        url: window.location.href,
        isPhishing: userIsPhishing,
        confidence: riskPercent / 100
    }, (response) => {
        if (response && response.success) {
            reportSection.innerHTML = `<div style="background: rgba(255,255,255,0.2); padding: 12px; border-radius: 12px; color: white; font-size: 13px; font-weight: 700;">✓ ${t.success}</div>`;
        } else {
            reportSection.innerHTML = `<div style="color: #ffffff; font-size: 13px; font-weight: bold; opacity: 0.8;">${t.error}</div>`;
        }
    });
}

function getPageFeatures() {
    return {
        has_password_field: (
            document.querySelectorAll('input[type="password"]').length > 0 ||
            document.querySelectorAll('input[type="text"]').length > 0 ||
            document.querySelectorAll('input[type="tel"]').length > 0
        ) ? 1 : 0,
        num_forms: document.forms.length,
        num_external_images: Array.from(document.images).filter(img => !img.src.includes(window.location.hostname)).length,
        num_links: document.links.length,
        has_hidden_fields: document.querySelectorAll('input[type="hidden"]').length > 0 ? 1 : 0,
        title_has_phish_word: /login|verify|update|account|bank|secure/i.test(document.title) ? 1 : 0
    };
}

window.addEventListener('load', () => {
    const pageData = getPageFeatures();
    chrome.runtime.sendMessage({ action: "analyzeContent", data: pageData });
});
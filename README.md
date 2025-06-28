<div align="center">
  <hr>
  
  <!-- Banner -->
  ![PhishSnitch Banner](https://github.com/ShivKushDev/PhishSnitch/blob/main/phishsnitchbanner.gif?raw=true)

  <hr>
  <h3 align="center">
    Email Threat Analyzer for detecting phishing attacks in real time. <br><br>
    <img src="https://img.shields.io/badge/Powered%20by-Gmail-red" height="24">
    <img src="https://img.shields.io/badge/Powered%20by-URLScan.io-blue" height="24">
    <img src="https://img.shields.io/badge/Developed%20by-ShivKushDev-brightgreen" height="24">
    <img src="https://img.shields.io/badge/Built%20for-CCubed-orange" height="24">
    <img src="https://img.shields.io/badge/Version-1.4-darkblue" height="24">
  </h3>
</div>

---

## 📌 Overview

**PhishSnitch** is a real-time email security tool that monitors your Gmail inbox and performs deep URL analysis to detect phishing links. It utilizes Gmail API, URLScan.io, SSL verification, domain reputation checks, and more to provide comprehensive alerting and logging.

---

## ✨ Features

- ✅ Real-time Gmail monitoring (secure OAuth2)
- 🔗 Automated URL extraction from HTML & plain text
- 🔁 Shortened URL resolution & redirect tracing
- 🛡️ URLScan.io integration for advanced analysis
- 🔍 SSL certificate & domain reputation validation
- ⚠️ Risk scoring system (Low → Critical)
- 🔔 Native desktop notifications
- 🧾 Persistent alert logging

---

## 📦 Installation

```bash
git clone https://github.com/ShivKushDev/PhishSnitch.git
cd PhishSnitch
pip install -r requirements.txt
```

### 🔧 Platform Notes

- **macOS**: `brew install terminal-notifier`
- **Linux**: `sudo apt-get install libnotify-bin`

---

## 🔐 Configuration

### 1. Google Cloud Setup

- Visit [Google Cloud Console](https://console.cloud.google.com)
- Create a project and enable the **Gmail API**
- Generate **OAuth 2.0 Client ID** (Desktop App)
- Download `credentials.json` and move it into:

```bash
mkdir config
mv credentials.json config/
```

### 2. URLScan.io API Key

- Sign up at [urlscan.io](https://urlscan.io)
- Copy your API key

### 3. Create Config File

Create `config/config.yaml`:

```yaml
gmail:
  credentials_path: config/credentials.json
  check_interval: 300

urlscan:
  api_key: "your-urlscan-api-key"
  cache_duration: 3600

security:
  whitelist: []
  blacklist: []
  risk_threshold: 70

alerts:
  history_path: data/alert_history.json
  desktop_notifications: true
```

---

## ▶️ Running PhishSnitch

```bash
python src/app.py
```

- Browser opens on first run to authorize Gmail access
- Logs saved in `logs/app.log`
- Alerts stored in `data/alert_history.json`

---

## 🚨 Risk Scoring

| Level    | Score Range | Indicators                               |
| -------- | ----------- | ---------------------------------------- |
| CRITICAL | 80–100      | Malicious domains, credential theft      |
| HIGH     | 60–79       | Redirect chains, no SSL, fresh domain    |
| MEDIUM   | 40–59       | Obfuscation, suspicious URLs             |
| LOW      | 20–39       | New domains, URL shorteners              |

---

## 🧪 Testing Guide

### ✅ Safe Test URLs

- `http://example.com`
- `https://test-phish.example.com`
- `http://bit.ly/test123`

### 📧 Sample Test Email

```
Subject: Reset your password
From: support@secure-login.example.com
Link: http://bit.ly/fake-login
```

### 🔬 Manual Test

```bash
python src/app.py
# Then send a test email and check logs/notifications
```

---

## 🧪 Run Tests

```bash
export PYTHONPATH=$PWD
python -m pytest -v tests/
python -m pytest --cov=src tests/
```

---

## 📸 Screenshots & Demos

### Real-time Monitoring & Alerts
![Alert Notifications](https://github.com/ShivKushDev/PhishSnitch/blob/main/alert_noti.png?raw=true)
*Desktop notifications for immediate threat awareness*

### Comprehensive Risk Analysis
![Critical Risk Alert](https://github.com/ShivKushDev/PhishSnitch/blob/main/critial_risk_alert_info.png?raw=true)
*Detailed analysis of critical security threats*

![High Risk Alert](https://github.com/ShivKushDev/PhishSnitch/blob/main/high_risk_alert.png?raw=true)
*High risk threat detection with detailed scoring*

![Medium Risk Alert](https://github.com/ShivKushDev/PhishSnitch/blob/main/medium_risk_alert.png?raw=true)
*Medium risk assessment with comprehensive analysis*

### Live Testing
![Real-time Testing](https://github.com/ShivKushDev/PhishSnitch/blob/main/realtime_test.png?raw=true)
*Real-time threat detection and analysis in action*

---

## 👨‍💻 Developer Utilities

```bash
black src/
mypy src/
```

---

## 🤝 Contributing

1. Fork this repo
2. Create a new branch: `git checkout -b feature-name`
3. Make your changes and commit
4. Run tests & format code
5. Submit a pull request 🎉

---

## 📝 License

Licensed under the [MIT License](LICENSE).

---

## 📚 References

- [📘 Gmail API Docs](https://developers.google.com/gmail/api)
- [📘 URLScan API](https://urlscan.io/docs/api/)
- [📘 win10toast](https://pypi.org/project/win10toast/)
- [📘 PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation)

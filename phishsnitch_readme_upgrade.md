

---

## 📌 Overview

PhishSnitch is a real-time email security tool that monitors your Gmail inbox and performs deep URL analysis to detect phishing links. It utilizes Gmail API, URLScan.io, SSL verification, domain reputation checks, and more to provide comprehensive alerting and logging.

---

## ✨ Features

- **Real-Time Gmail Monitoring** (OAuth2 secure access)
- **Automated URL Extraction** (HTML & plain text)
- **Redirect Unwinding & Short Link Resolution**
- **URLScan.io Threat Intel Integration**
- **SSL Certificate & Domain Reputation Checks**
- **Risk-Based Alert Scoring** (Low to Critical)
- **Desktop Notifications** via `win10toast`, `terminal-notifier`, or `libnotify`
- **Persistent Alert History Logs**

---

## 📦 Installation

```bash
git clone https://github.com/ShivKushDev/PhishSnitch.git
cd PhishSnitch
pip install -r requirements.txt
```

### 🔧 Platform Notes:

- **macOS**: `brew install terminal-notifier`
- **Linux**: `sudo apt-get install libnotify-bin`

---

## 🔐 Configuration

1. **Google Cloud Setup**

   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Enable **Gmail API** and create **OAuth Desktop credentials**
   - Download the credentials file and place in:
     ```bash
     mkdir config
     mv credentials.json config/
     ```

2. **URLScan.io Setup**

   - Create an account at [urlscan.io](https://urlscan.io)
   - Copy your API key

3. **Create **``

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

- A browser will open for Gmail authorization the first time.
- Alert logs appear in `logs/app.log`
- JSON history is saved to `data/alert_history.json`

---

## 🚨 Risk Scoring

| Level    | Score Range | Indicators                               |
| -------- | ----------- | ---------------------------------------- |
| CRITICAL | 80-100      | Malicious domain + credential harvesting |
| HIGH     | 60-79       | Suspicious redirects, new domain, no SSL |
| MEDIUM   | 40-59       | Link obfuscation or mixed content        |
| LOW      | 20-39       | URL shorteners, recently registered      |

---

## 🧪 Testing Guide

### ✅ Safe Test URLs

- `http://example.com`
- `https://test-phish.example.com`
- `http://bit.ly/test`

### 📧 Sample Emails

```
Subject: Reset your password
From: support@secure-login.example.com
Link: http://bit.ly/fake-login
```

### 🔬 Manual Testing

```bash
python src/app.py
# Then send a test email and observe logs or notifications
```

---

## 🧪 Running Unit Tests

```bash
export PYTHONPATH=$PWD
python -m pytest -v tests/
python -m pytest --cov=src tests/
```

---

## 📸 Screenshots & Demos

-
-

---

## 👨‍💻 Developer Utilities

```bash
black src/
mypy src/
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a new branch: `git checkout -b feature-name`
3. Commit your changes with clear messages
4. Run tests & format code
5. Submit a pull request

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

## 📚 Resources

- [📘 Gmail API Python Docs](https://developers.google.com/gmail/api)
- [📘 URLScan API Docs](https://urlscan.io/docs/api/)
- [📘 win10toast](https://pypi.org/project/win10toast/)
- [📘 PyYAML Docs](https://pyyaml.org/wiki/PyYAMLDocumentation)

---

## ☕ Support

Enjoying PhishSnitch? Show support:


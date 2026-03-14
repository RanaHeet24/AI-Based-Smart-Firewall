# AI-Based Smart Firewall

An AI-powered Smart Firewall with a **browser extension** that automatically intercepts URLs and blocks phishing, malware, and piracy sites in real-time — no proxy configuration required.

## 🌟 Features

- **Browser Extension**: Automatically intercepts every URL you visit and checks it against the AI engine.
- **Phishing Detection**: Machine learning model trained to identify malicious URLs.
- **Piracy Detection**: Dedicated module to detect piracy-related content.
- **Malware & Content Security**: Scans for fake download buttons, malicious HTML, and drive-by downloads.
- **Real-Time Dashboard**: Streamlit UI to visualize all firewall events, threat statistics, and decision logs.
- **Explainable AI (XAI)**: Every block/warn decision is explained with per-layer reasoning.

## 📂 Project Structure

```
ai-smart-firewall/
├── api/                  # Flask API Backend (talks to the browser extension)
│   └── server.py
├── extension/            # Chrome Browser Extension
│   ├── manifest.json
│   ├── background.js     # Service worker that intercepts URLs
│   ├── popup.html        # Extension popup UI
│   ├── popup.js
│   └── blocked.html      # Warning page shown on threat detection
├── dashboard/            # Streamlit Monitoring Dashboard
│   └── dashboard.py
├── src/                  # Core AI modules
│   ├── firewall_engine.py
│   ├── risk_engine.py
│   ├── piracy_detector.py
│   ├── content_analyzer.py
│   ├── heuristics.py
│   └── domain_reputation.py
├── models/               # Trained ML models
├── data/                 # Datasets
├── logs/                 # Firewall event logs (read by dashboard)
├── utils/
├── requirements.txt
└── main.py               # Launches API Server + Dashboard together
```

## 🚀 Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Backend
```bash
python main.py
```
This launches:
- 🔌 **API Server** at `http://127.0.0.1:5000`
- 📊 **Dashboard** at `http://localhost:8501`

### 3. Install the Browser Extension

1. Open **Google Chrome** and go to `chrome://extensions`
2. Enable **Developer Mode** (toggle in the top-right corner)
3. Click **"Load unpacked"**
4. Select the `extension/` folder from this project directory
5. The 🛡️ AI Smart Firewall icon will appear in your browser toolbar

### 4. Browse the Web — You're Protected!

The extension will now automatically scan every URL you visit. If a threat is detected:
- **BLOCK** → You are redirected to a warning page and the site is stopped.
- **WARN** → An orange `⚠` badge appears on the extension icon.
- **ALLOW** → The site is safe, you browse normally.

## 🛠️ Built With

- **Python / Flask** (API Backend)
- **Scikit-learn / Pandas / Numpy** (Machine Learning)
- **Streamlit / Plotly** (Dashboard)
- **Chrome Extension APIs** (Manifest V3, `webNavigation`, `storage`)
- **BeautifulSoup4 / Requests** (Content Analysis)

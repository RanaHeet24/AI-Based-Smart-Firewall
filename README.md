# AI-Based Smart Firewall

A multi-layered AI-powered smart firewall system designed to detect and block phishing, piracy, and other malicious activities in real-time. The system leverages machine learning models to analyze URLs and web content, providing an intelligent proxy server and an interactive monitoring dashboard.

## 🌟 Features

- **AI Proxy Server**: A Flask-based proxy that intercepts and analyzes web traffic.
- **Real-Time Monitoring Dashboard**: A Streamlit interface to visualize firewall activities, logs, and threat statistics.
- **Phishing Detection**: Uses a trained machine learning model (`scikit-learn`) to identify malicious URLs.
- **Piracy Detection**: Dedicated modules to detect piracy-related content.
- **Multi-Layered Firewall Engine**: Extensible architecture to add more security layers.

## 📂 Project Structure

- `main.py`: The entry point script that starts both the proxy server and the dashboard.
- `proxy/`: Contains the Flask proxy server implementation.
- `dashboard/`: Contains the Streamlit monitoring dashboard.
- `src/`: Source code for the firewall engine, piracy detector, and model training scripts.
- `models/`: Stores the trained machine learning models (e.g., `phishing_detection_model.pkl`).
- `data/`: Datasets for training the machine learning models.
- `logs/`: Directory where the firewall logs its activities.

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RanaHeet24/AI-Based-Smart-Firewall.git
   cd AI-Based-Smart-Firewall
   ```

2. **Install the dependencies:**
   Make sure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

To start the AI Smart Firewall system, simply run the main script:

```bash
python main.py
```

This will launch:
- 🛡️ **Proxy Server** at `http://127.0.0.1:5000`
- 📊 **Streamlit Dashboard** at `http://localhost:8501`

### Testing the Proxy

You can test the proxy by prepending the proxy URL to any website:
- **Safe URL Test:** `http://127.0.0.1:5000/https://www.google.com`
- **Bad URL Test:** `http://127.0.0.1:5000/http://suspicious-login-verify.xyz/login`

Press `Ctrl+C` in the terminal to stop all services.

## 🛠️ Built With

- **Python**
- **Flask** (Proxy Server)
- **Streamlit** (Dashboard)
- **Scikit-learn / Pandas / Numpy** (Machine Learning & Data Processing)
- **BeautifulSoup4 / Requests** (Web Scraping & API)

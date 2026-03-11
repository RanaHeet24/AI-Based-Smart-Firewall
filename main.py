import os
import subprocess
import time
import sys
import threading

def start_flask_proxy():
    """Starts the Flask Proxy Server."""
    print("🚀 Starting AI Smart Firewall Proxy Server on port 5000...")
    proxy_script = os.path.join("proxy", "proxy_server.py")
    return subprocess.Popen([sys.executable, proxy_script])

def start_streamlit_dashboard():
    """Starts the Streamlit Dashboard."""
    print("📊 Starting Streamlit Dashboard on port 8501...")
    dashboard_script = os.path.join("dashboard", "dashboard.py")
    return subprocess.Popen([sys.executable, "-m", "streamlit", "run", dashboard_script])

def check_model_exists():
    """Checks if the ML model is trained and available."""
    model_path = os.path.join("models", "phishing_detection_model.pkl")
    if not os.path.exists(model_path):
        print("⚠️  Warning: ML Model not found!")
        print("🔄 Training a new model automatically...")
        train_script = os.path.join("src", "train_model.py")
        subprocess.run([sys.executable, train_script])
        print("✅ Model trained successfully!\n")

def main():
    print("==============================================")
    print("      🧠 AI Smart Firewall System Boot        ")
    print("==============================================\n")

    # Ensure we are in the project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    # 1. Setup & Checks
    check_model_exists()

    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)

    # 2. Start Services
    try:
        # Start Proxy Server
        proxy_process = start_flask_proxy()
        
        # Give it a second to bind
        time.sleep(2)
        
        # Start Dashboard
        dashboard_process = start_streamlit_dashboard()

        print("\n✅ System is fully operational!")
        print("👉 Proxy is running at:      http://127.0.0.1:5000")
        print("👉 Dashboard is running at:  http://localhost:8501\n")
        print("Test a safe URL: http://127.0.0.1:5000/https://www.google.com")
        print("Test a bad URL:  http://127.0.0.1:5000/http://suspicious-login-verify.xyz/login\n")
        print("Press Ctrl+C to stop all services.")

        # Keep main thread alive
        proxy_process.wait()
        dashboard_process.wait()

    except KeyboardInterrupt:
        print("\n🛑 Shutting down AI Smart Firewall Services...")
        proxy_process.terminate()
        dashboard_process.terminate()
        print("✅ Shutdown complete.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        if 'proxy_process' in locals(): proxy_process.terminate()
        if 'dashboard_process' in locals(): dashboard_process.terminate()
        sys.exit(1)

if __name__ == "__main__":
    main()

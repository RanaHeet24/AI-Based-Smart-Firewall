import os
import subprocess
import time
import sys

def start_api_server():
    """Starts the Flask API Backend Server."""
    print("🚀 Starting AI Smart Firewall API Server on port 5000...")
    api_script = os.path.join("api", "server.py")
    return subprocess.Popen([sys.executable, api_script])

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
        # Start API Server (replaces old proxy server)
        api_process = start_api_server()

        # Give it a moment to bind to the port
        time.sleep(2)

        # Start Dashboard
        dashboard_process = start_streamlit_dashboard()

        print("\n✅ System is fully operational!")
        print("👉 API Backend is running at:   http://127.0.0.1:5000")
        print("👉 Dashboard is running at:     http://localhost:8501\n")
        print("📌 Load the browser extension from the `extension/` folder in Chrome.")
        print("   Go to: chrome://extensions → Enable Developer Mode → Load Unpacked")
        print("\nPress Ctrl+C to stop all services.")

        # Keep main thread alive
        api_process.wait()
        dashboard_process.wait()

    except KeyboardInterrupt:
        print("\n🛑 Shutting down AI Smart Firewall Services...")
        api_process.terminate()
        dashboard_process.terminate()
        print("✅ Shutdown complete.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        if 'api_process' in locals(): api_process.terminate()
        if 'dashboard_process' in locals(): dashboard_process.terminate()
        sys.exit(1)

if __name__ == "__main__":
    main()

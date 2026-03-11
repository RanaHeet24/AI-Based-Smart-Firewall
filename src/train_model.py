import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import logging
import numpy as np

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def train_model():
    """
    Trains a Random Forest classifier for malicious URL detection.
    Reads processed data, trains, evaluates, and saves the model.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    processed_data_path = os.path.join(base_dir, "data", "processed", "cleaned_dataset.csv")
    model_save_path = os.path.join(base_dir, "models", "phishing_detection_model.pkl")

    # 1. Load processed dataset
    if not os.path.exists(processed_data_path):
        logging.warning(f"Processed dataset not found at: {processed_data_path}")
        logging.info("Generating a synthetic dataset for testing purposes...")
        df = generate_synthetic_data(processed_data_path)
    else:
        try:
            df = pd.read_csv(processed_data_path)
        except pd.errors.EmptyDataError:
            logging.warning("Processed dataset file exists but is empty.")
            logging.info("Falling back to generating a synthetic dataset...")
            df = generate_synthetic_data(processed_data_path)
        except Exception as e:
            logging.error(f"Error reading dataset: {e}")
            return
        
    if df.empty:
        logging.error("Dataset is empty. Cannot train the model.")
        return

    logging.info(f"Dataset loaded. Shape: {df.shape}")

    # Ensure 'label' column exists
    if 'label' not in df.columns:
         logging.error("The dataset must contain a 'label' column (1 = legitimate, 0 = malicious).")
         return

    # Separate features (X) and labels (y)
    X = df.drop(columns=['label'])
    y = df['label']

    # 2. Split dataset into training and testing sets (80/20 split)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    logging.info(f"Data split - Training set: {X_train.shape[0]} samples, Testing set: {X_test.shape[0]} samples.")

    # 3. Train a Random Forest classifier
    logging.info("Training Random Forest Classifier...")
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_classifier.fit(X_train, y_train)

    # 4. Evaluate model accuracy
    logging.info("Evaluating the model on test data...")
    y_pred = rf_classifier.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    logging.info(f"Model Accuracy: {accuracy * 100:.2f}%")

    # 5. Print confusion matrix and classification report
    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {accuracy * 100:.2f}%\n")
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Malicious (0)', 'Legitimate (1)']))

    # 6. Save the trained model
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    joblib.dump(rf_classifier, model_save_path)
    logging.info(f"Trained model saved successfully to: {model_save_path}")

def generate_synthetic_data(save_path):
    """Generates synthetic feature data for testing the pipeline if no data exists."""
    import numpy as np
    
    num_samples = 1000
    data = []
    
    for _ in range(num_samples // 2):
        # Legitimate (1) features based on our feature extraction
        data.append([
            np.random.randint(20, 50), # URL length
            np.random.randint(1, 3),   # Number of dots
            0,                         # Subdomains
            0,                         # IP Address presence
            np.random.randint(0, 2),   # Special chars
            1,                         # HTTPS
            np.random.randint(0, 5),   # Digits
            0,                         # Suspicious keywords
            1                          # Label: Legitimate
        ])
        
    for _ in range(num_samples // 2):
        # Malicious (0) features
        data.append([
            np.random.randint(40, 100), # URL length
            np.random.randint(2, 6),    # Number of dots
            np.random.randint(1, 4),    # Subdomains
            np.random.choice([0, 1], p=[0.7, 0.3]), # IP Address presence
            np.random.randint(2, 10),   # Special chars
            np.random.choice([0, 1], p=[0.6, 0.4]), # HTTPS
            np.random.randint(2, 15),   # Digits
            np.random.randint(0, 3),    # Suspicious keywords
            0                           # Label: Malicious
        ])

    columns = [
        'url_length', 'num_dots', 'num_subdomains', 'has_ip', 
        'num_special_chars', 'has_https', 'num_digits_in_domain', 
        'suspicious_keywords_count', 'label'
    ]
    df = pd.DataFrame(data, columns=columns).sample(frac=1).reset_index(drop=True)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    df.to_csv(save_path, index=False)
    logging.info(f"Synthetic data saved to {save_path}")
    return df

if __name__ == "__main__":
    train_model()

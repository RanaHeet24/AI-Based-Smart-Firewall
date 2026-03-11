import os
import pandas as pd
import logging
import glob

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_datasets(raw_data_dir):
    """Loads all CSV datasets from the raw directory and merges them."""
    all_files = glob.glob(os.path.join(raw_data_dir, "*.csv"))
    if not all_files:
        logging.warning(f"No CSV files found in {raw_data_dir}.")
        return pd.DataFrame()

    df_list = []
    for file in all_files:
        try:
            df = pd.read_csv(file)
            logging.info(f"Loaded {file} with shape {df.shape}")
            df_list.append(df)
        except Exception as e:
            logging.error(f"Error loading {file}: {e}")

    if df_list:
        merged_df = pd.concat(df_list, ignore_index=True)
        logging.info(f"Merged dataset shape: {merged_df.shape}")
        return merged_df
    return pd.DataFrame()

def clean_data(df):
    """Handles missing values, removes duplicates, and normalizes columns."""
    logging.info("Starting data cleaning...")
    
    # 1. Normalize column names (lowercase, replace spaces with underscores)
    df.columns = [col.strip().lower().replace(" ", "_").replace("-", "_") for col in df.columns]
    logging.info("Normalized column names.")

    # 2. Handle missing values (Drop rows with missing values for now)
    initial_len = len(df)
    df = df.dropna()
    logging.info(f"Dropped {initial_len - len(df)} rows with missing values.")

    # 3. Remove duplicates
    initial_len = len(df)
    df = df.drop_duplicates()
    logging.info(f"Dropped {initial_len - len(df)} duplicate rows.")

    return df

def map_labels(df, label_col="label"):
    """
    Converts labels to binary classification:
    1 = legitimate
    0 = malicious
    
    Assuming original labels might be like "legitimate"/"phishing" or 1/-1
    """
    if label_col not in df.columns:
        # Try to find a column that looks like a label
        possible_labels = [col for col in df.columns if "class" in col or "target" in col or "status" in col or "result" in col]
        if possible_labels:
            label_col = possible_labels[0]
            logging.info(f"Label column not found, using '{label_col}' instead.")
        else:
            logging.warning("No label column found. Cannot map labels.")
            return df

    logging.info(f"Mapping labels in column '{label_col}'...")
    
    # Check unique values to determine mapping strategy
    unique_vals = df[label_col].unique()
    logging.info(f"Unique label values found: {unique_vals}")

    def convert_label(val):
        """Helper to standardize labels to 1 (legitimate) or 0 (malicious)."""
        val_str = str(val).strip().lower()
        if val_str in ['1', 'legitimate', 'safe', 'good', 'benign']:
            return 1
        elif val_str in ['-1', '0', 'phishing', 'malicious', 'bad', 'suspicious']:
            return 0
        else:
            return None # Unrecognized

    df[label_col] = df[label_col].apply(convert_label)
    
    # Drop any unrecognized labels
    initial_len = len(df)
    df = df.dropna(subset=[label_col])
    if len(df) < initial_len:
         logging.info(f"Dropped {initial_len - len(df)} rows with unrecognized labels.")

    # Ensure integer type for labels
    df[label_col] = df[label_col].astype(int)
    
    # Rename column to standard 'label' if it wasn't
    if label_col != "label":
        df.rename(columns={label_col: "label"}, inplace=True)
        
    logging.info("Labels mapped successfully (1=legitimate, 0=malicious).")
    return df

def preprocess_and_save():
    """Main pipeline for preprocessing."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw_dir = os.path.join(base_dir, "data", "raw")
    processed_dir = os.path.join(base_dir, "data", "processed")
    
    # Ensure processed directory exists
    os.makedirs(processed_dir, exist_ok=True)
    
    output_path = os.path.join(processed_dir, "cleaned_dataset.csv")

    logging.info("--- Starting Data Preprocessing Pipeline ---")
    
    df = load_datasets(raw_dir)
    
    if df.empty:
        logging.error("No data to process. Exiting.")
        return

    df = clean_data(df)
    df = map_labels(df)
    
    df.to_csv(output_path, index=False)
    logging.info(f"Cleaned dataset saved to: {output_path}")
    logging.info("--- Data Preprocessing Complete ---")

if __name__ == "__main__":
    preprocess_and_save()

import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(name, log_file="system.log", level=logging.INFO):
    """
    Configures and returns a production-ready logger instance.
    Writes to both console and a rotating file handler.
    """
    logger = logging.getLogger(name)
    
    # Optional: If logger already has handlers, avoid adding them again
    if logger.handlers:
        return logger
        
    logger.setLevel(level)

    # Define log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # 1. Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 2. File Handler (Rotating)
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    file_path = os.path.join(logs_dir, log_file)
    # 5 MB max per file, keep 3 backups
    file_handler = RotatingFileHandler(
        file_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

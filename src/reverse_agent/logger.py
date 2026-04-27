import logging
import sys
from pathlib import Path

def setup_logger(output_dir: Path, name="reverse_agent"):
    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file_path = log_dir / "agent.log"

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Remove all existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create a file handler
    file_handler = logging.FileHandler(log_file_path)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Create a console handler with a different format
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger

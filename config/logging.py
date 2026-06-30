import logging
import sys

def setup_logging(level=logging.INFO):
    """Configure global structured logging."""
    logger = logging.getLogger("CrewAIFoundation")
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    # Suppress verbose third-party logs
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    
    return logger

logger = setup_logging()

import logging

def setup_logger():
    logging.basicConfig(
        filename="scan_log.txt",
        level=logging.INFO,
        format="%(asctime)s - %(message)s"
    )
    return logging.getLogger(__name__)


logger = setup_logger()

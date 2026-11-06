import ipaddress
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DATES = BASE / "data"
REPORTS = BASE / "reports"
BLOCKLIST = BASE / "blocklist_proposal.txt"
DATA_DIR = DATES
REPORTS_DIR = REPORTS
BLOCKLIST_FILE = BLOCKLIST

LMSTUDIO_URL = os.getenv("LMSTUDIO_URL", "http://localhost_1234/v1")
MODEL = os.getenv("MODEL", "qwen3.5-4b")

INTERNAL_NETWORK = ipaddress.ip_network("10.0.0.0/8")
BRUTE_FORCE_THRESHOLD = 10
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RETRIES = 25

# 
MAX_STEPS = 25
MODEL_NAME = MODEL
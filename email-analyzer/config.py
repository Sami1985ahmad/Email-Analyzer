"""Configuration and API key settings for Email Security & Header Analyzer."""

import os

# VirusTotal API Key: Read from environment or configure here
VT_API_KEY = os.getenv("VT_API_KEY", "")

# Request timeout in seconds for external queries
REQUEST_TIMEOUT = 10

# DNS resolution timeout in seconds
DNS_TIMEOUT = 5

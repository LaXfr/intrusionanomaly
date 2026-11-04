import os

API_BASE_URL = os.getenv("NII_DASHBOARD_API_URL", "http://127.0.0.1:8000/api/v1").rstrip("/")
REQUEST_TIMEOUT = float(os.getenv("NII_DASHBOARD_TIMEOUT", "10"))

import os
import sys

# Configure the module before import; no real AWS credentials or network are used.
os.environ.update(
    {
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "HOSTED_ZONE_ID": "Z0123456789ABCDEFGHIJ",
        "RECORD_NAME": "home.example.com",
        "TTL": "60",
        "CREDENTIAL_PARAM_NAME": "/ddns/credentials",
    }
)
os.environ.pop("AWS_PROFILE", None)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

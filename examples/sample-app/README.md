# Sample App

This intentionally vulnerable Python application is the target used throughout the KratosComply demo. It includes:

- Hardcoded API tokens and passwords for the agent to detect.
- A fake public S3 ACL reference (`public-read`).
- Minimal pytest coverage for smoke testing.

## Running locally

```bash
cd examples/sample-app
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

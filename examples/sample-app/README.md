# Sample App

This intentionally vulnerable Python application is the target used throughout the KratosComply demo. It includes:

- Hardcoded API tokens and passwords for the agent to detect.
- A Terraform bucket definition with a public S3 ACL (`infra/bucket.tf`).
- Minimal pytest coverage for smoke testing.
- Auto-fix patch suggestions placed under `patches/` once the agent is run with
  `--generate-patches`.

## Running locally

```bash
cd examples/sample-app
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

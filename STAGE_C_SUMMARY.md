# Stage C Summary – Patcher + Sandbox Validation

## What was added
- Deterministic patch generator for Python secrets and Terraform ACLs with `.env.template`
  suggestions and metadata per finding.
- Sandbox harness that applies patches inside a temp copy, runs pytest (or a fallback),
  and records whether each diff is safe to auto-apply.
- New CLI capabilities: `--generate-patches` on `scan` plus `apply-patch` for explicit
  application, along with metadata/README/docs updates and sample patch outputs.

## How to verify Stage C
```bash
source .venv/bin/activate  # or recreate the env
pytest -q
cd agent
python -m agent.cli scan ../examples/sample-app \
  --output examples/sample-app/aegis-report.json \
  --generate-patches
ls ../examples/sample-app/patches
python -m agent.cli apply-patch ../examples/sample-app/patches/0001-fix-F001.diff \
  --workspace ../examples/sample-app  # review the diff before running
cd ..
```

## Sample patch (first 10 lines)
```
--- a/app.py
+++ b/app.py
@@
-PAYMENT_API_TOKEN = "tok_live_51_insecure"
+PAYMENT_API_TOKEN = os.getenv('PAYMENT_API_TOKEN', "tok_live_51_insecure")
```

#!/bin/bash
# Test script to demonstrate KratosComply agent functionality

set -e

echo "========================================="
echo "KratosComply Agent Test Script"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR="./test-workspace"
KEYSTORE_DIR="$HOME/.kratos/keys"

echo -e "${BLUE}Step 1: Setting up test workspace...${NC}"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Create a test Python file with violations
cat > "$TEST_DIR/app.py" << 'EOF'
"""Sample application with compliance violations."""

# Hardcoded secret (violation)
API_KEY = "sk_live_1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"

# Configuration
DEBUG = True
HOST = "0.0.0.0"  # Insecure binding

def connect_database():
    """Connect to database."""
    # Another hardcoded secret
    password = "admin123"
    return f"postgresql://user:{password}@localhost/db"

if __name__ == "__main__":
    print("App running")
EOF

# Create a Terraform file with insecure ACL
mkdir -p "$TEST_DIR/infra"
cat > "$TEST_DIR/infra/bucket.tf" << 'EOF'
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  
  # Insecure ACL (violation)
  acl = "public-read"
}

resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
  acl    = "private"  # OK
}
EOF

# Create a config file with secrets
cat > "$TEST_DIR/config.yaml" << 'EOF'
database:
  host: localhost
  password: "secret123"  # Violation
  user: admin

api:
  key: "sk_test_abcdef123456"  # Violation
EOF

echo -e "${GREEN}✓ Test workspace created${NC}"
echo ""

echo -e "${BLUE}Step 2: Generating keypair...${NC}"
mkdir -p "$KEYSTORE_DIR"
python -m agent.cli generate-key --keystore "$KEYSTORE_DIR" || {
    echo -e "${YELLOW}Note: Keys may already exist${NC}"
}
echo -e "${GREEN}✓ Keypair ready${NC}"
echo ""

echo -e "${BLUE}Step 3: Scanning workspace...${NC}"
OUTPUT_REPORT="$TEST_DIR/compliance-report.json"
python -m agent.cli scan "$TEST_DIR" \
    --output "$OUTPUT_REPORT" \
    --keystore "$KEYSTORE_DIR" \
    --project-name "test-project" \
    --generate-patches

echo ""
echo -e "${GREEN}✓ Scan complete${NC}"
echo ""

echo -e "${BLUE}Step 4: Displaying report summary...${NC}"
if [ -f "$OUTPUT_REPORT" ]; then
    echo ""
    echo "Report Location: $OUTPUT_REPORT"
    echo ""
    echo "Report Summary:"
    python3 << 'PYTHON'
import json
import sys

try:
    with open(sys.argv[1], 'r') as f:
        report = json.load(f)
    
    print(f"  Project: {report['project']['name']}")
    print(f"  Standards: {', '.join(report['standards'])}")
    print(f"  Total Findings: {len(report['findings'])}")
    print(f"  Merkle Root: {report['merkle_root'][:16]}...")
    print(f"  Signature: {report['agent_signature'][:16]}...")
    print("")
    print("  Metrics:")
    for key, value in report['metrics'].items():
        print(f"    {key}: {value}")
    print("")
    print("  Sample Findings:")
    for i, finding in enumerate(report['findings'][:5], 1):
        print(f"    {i}. {finding['type']} - {finding['severity']}")
        print(f"       File: {finding['file']}:{finding['line']}")
        print(f"       Frameworks: {', '.join(finding.get('compliance_frameworks_affected', []))}")
        print("")
except Exception as e:
    print(f"Error reading report: {e}")
PYTHON
    "$OUTPUT_REPORT"
else
    echo -e "${YELLOW}Report file not found${NC}"
fi

echo ""
echo -e "${BLUE}Step 5: Checking generated patches...${NC}"
PATCHES_DIR="$TEST_DIR/patches"
if [ -d "$PATCHES_DIR" ]; then
    PATCH_COUNT=$(find "$PATCHES_DIR" -name "*.diff" | wc -l)
    echo -e "${GREEN}✓ Found $PATCH_COUNT patch(es)${NC}"
    if [ "$PATCH_COUNT" -gt 0 ]; then
        echo ""
        echo "Patches:"
        ls -lh "$PATCHES_DIR"/*.diff 2>/dev/null || true
    fi
else
    echo -e "${YELLOW}No patches directory found${NC}"
fi

echo ""
echo -e "${BLUE}Step 6: Displaying public key (for verification)...${NC}"
python -m agent.cli public-key --keystore "$KEYSTORE_DIR" || {
    echo -e "${YELLOW}Could not retrieve public key${NC}"
}

echo ""
echo "========================================="
echo -e "${GREEN}Test Complete!${NC}"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Review the report: $OUTPUT_REPORT"
echo "  2. Review patches in: $PATCHES_DIR"
echo "  3. Upload report to backend for verification"
echo "  4. Create attestation for audit purposes"
echo ""


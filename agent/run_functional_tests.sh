#!/bin/bash
# Comprehensive functional test script for KratosComply agent

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
TEST_DIR="./functional-test-workspace"
KEYSTORE_DIR="$HOME/.kratos/keys"
REPORT_FILE="$TEST_DIR/compliance-report.json"
PASSED=0
FAILED=0

echo "========================================="
echo "KratosComply Agent Functional Tests"
echo "========================================="
echo ""

# Helper functions
pass_test() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    ((PASSED++))
}

fail_test() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    ((FAILED++))
}

# Test 1: Setup and Key Generation
echo -e "${BLUE}Test 1: Key Generation${NC}"
mkdir -p "$KEYSTORE_DIR"
if python -m agent.cli generate-key --keystore "$KEYSTORE_DIR" 2>&1 | grep -q "Private key written"; then
    pass_test "Key generation"
else
    fail_test "Key generation"
fi
echo ""

# Test 2: Create Test Workspace
echo -e "${BLUE}Test 2: Test Workspace Setup${NC}"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Create test files with known violations
cat > "$TEST_DIR/secrets.py" << 'EOF'
API_KEY = "sk_live_1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"
token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
EOF

cat > "$TEST_DIR/infra.tf" << 'EOF'
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl = "public-read"
}
EOF

if [ -f "$TEST_DIR/secrets.py" ] && [ -f "$TEST_DIR/infra.tf" ]; then
    pass_test "Test workspace creation"
else
    fail_test "Test workspace creation"
fi
echo ""

# Test 3: Run Agent Scan
echo -e "${BLUE}Test 3: Agent Scan Execution${NC}"
if python -m agent.cli scan "$TEST_DIR" \
    --output "$REPORT_FILE" \
    --keystore "$KEYSTORE_DIR" \
    --project-name "functional-test" 2>&1 | grep -q "Report written"; then
    pass_test "Agent scan execution"
else
    fail_test "Agent scan execution"
fi
echo ""

# Test 4: Report File Exists
echo -e "${BLUE}Test 4: Report File Generation${NC}"
if [ -f "$REPORT_FILE" ]; then
    pass_test "Report file exists"
else
    fail_test "Report file exists"
fi
echo ""

# Test 5: Report Structure Validation
echo -e "${BLUE}Test 5: Report Structure Validation${NC}"
python3 << 'PYTHON'
import json
import sys

try:
    with open(sys.argv[1], 'r') as f:
        report = json.load(f)
    
    required_fields = [
        'report_version', 'project', 'standards', 'findings',
        'metrics', 'merkle_root', 'agent_signature', 'agent_version'
    ]
    
    missing = [f for f in required_fields if f not in report]
    if missing:
        print(f"Missing fields: {missing}")
        sys.exit(1)
    
    # Validate project structure
    if 'name' not in report['project']:
        print("Missing project.name")
        sys.exit(1)
    
    # Validate metrics structure
    required_metrics = ['critical', 'high', 'medium', 'low', 'risk_score']
    missing_metrics = [m for m in required_metrics if m not in report['metrics']]
    if missing_metrics:
        print(f"Missing metrics: {missing_metrics}")
        sys.exit(1)
    
    # Validate merkle root format
    if len(report['merkle_root']) != 64:
        print(f"Invalid merkle root length: {len(report['merkle_root'])}")
        sys.exit(1)
    
    # Validate signature exists
    if not report['agent_signature']:
        print("Missing agent signature")
        sys.exit(1)
    
    print("Report structure valid")
    sys.exit(0)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
PYTHON
"$REPORT_FILE"

if [ $? -eq 0 ]; then
    pass_test "Report structure validation"
else
    fail_test "Report structure validation"
fi
echo ""

# Test 6: Findings Detection
echo -e "${BLUE}Test 6: Findings Detection${NC}"
FINDING_COUNT=$(python3 << 'PYTHON'
import json
import sys
with open(sys.argv[1], 'r') as f:
    report = json.load(f)
print(len(report['findings']))
PYTHON
"$REPORT_FILE")

if [ "$FINDING_COUNT" -gt 0 ]; then
    pass_test "Findings detected ($FINDING_COUNT findings)"
else
    fail_test "Findings detected (expected > 0, got $FINDING_COUNT)"
fi
echo ""

# Test 7: Finding Structure Validation
echo -e "${BLUE}Test 7: Finding Structure Validation${NC}"
python3 << 'PYTHON'
import json
import sys

try:
    with open(sys.argv[1], 'r') as f:
        report = json.load(f)
    
    if not report['findings']:
        print("No findings to validate")
        sys.exit(1)
    
    finding = report['findings'][0]
    required_fields = [
        'id', 'type', 'file', 'line', 'snippet', 'severity',
        'confidence', 'evidence_hash'
    ]
    
    missing = [f for f in required_fields if f not in finding]
    if missing:
        print(f"Missing fields in finding: {missing}")
        sys.exit(1)
    
    # Validate evidence_hash format
    if len(finding['evidence_hash']) != 64:
        print(f"Invalid evidence_hash length: {len(finding['evidence_hash'])}")
        sys.exit(1)
    
    # Validate severity
    valid_severities = ['critical', 'high', 'medium', 'low']
    if finding['severity'] not in valid_severities:
        print(f"Invalid severity: {finding['severity']}")
        sys.exit(1)
    
    print("Finding structure valid")
    sys.exit(0)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
PYTHON
"$REPORT_FILE"

if [ $? -eq 0 ]; then
    pass_test "Finding structure validation"
else
    fail_test "Finding structure validation"
fi
echo ""

# Test 8: Public Key Retrieval
echo -e "${BLUE}Test 8: Public Key Retrieval${NC}"
if python -m agent.cli public-key --keystore "$KEYSTORE_DIR" 2>&1 | grep -qE "^[0-9a-f]{64}$"; then
    pass_test "Public key retrieval"
else
    fail_test "Public key retrieval"
fi
echo ""

# Test 9: Merkle Root Consistency
echo -e "${BLUE}Test 9: Merkle Root Consistency${NC}"
python3 << 'PYTHON'
import json
import sys
from hashlib import sha256

try:
    with open(sys.argv[1], 'r') as f:
        report = json.load(f)
    
    # Recompute merkle root from findings
    hashes = [f['evidence_hash'].lower() for f in report['findings']]
    hashes.sort()
    
    if not hashes:
        # Empty merkle root
        computed = sha256(b"").hexdigest()
    else:
        # Simple merkle tree computation
        nodes = [bytes.fromhex(h) for h in hashes]
        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])
            nodes = [sha256(left + right).digest() for left, right in zip(nodes[0::2], nodes[1::2])]
        computed = nodes[0].hex()
    
    if computed.lower() == report['merkle_root'].lower():
        print("Merkle root matches")
        sys.exit(0)
    else:
        print(f"Merkle root mismatch: computed={computed}, reported={report['merkle_root']}")
        sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
PYTHON
"$REPORT_FILE"

if [ $? -eq 0 ]; then
    pass_test "Merkle root consistency"
else
    fail_test "Merkle root consistency"
fi
echo ""

# Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}Failed: $FAILED${NC}"
    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi


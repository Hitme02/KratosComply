#!/bin/bash
# End-to-End Test Script for KratosComply
# Tests the complete workflow: scan → upload → verify → attest

set -e

echo "========================================="
echo "KratosComply End-to-End Test"
echo "========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost:5173}"
TEST_PROJECT="${TEST_PROJECT:-examples/sample-app}"
KEYSTORE_DIR="${HOME}/.kratos/keys"
REPORT_FILE="/tmp/kratos-test-report.json"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

test_step() {
    local name="$1"
    shift
    echo -e "${BLUE}Testing: ${name}${NC}"
    if "$@"; then
        echo -e "${GREEN}✓ ${name} passed${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ ${name} failed${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo -e "${BLUE}Step 1: Checking prerequisites...${NC}"

# Check if backend is running
if ! curl -s "${BACKEND_URL}/" > /dev/null 2>&1; then
    echo -e "${RED}✗ Backend not running at ${BACKEND_URL}${NC}"
    echo "   Start it with: docker-compose up backend"
    exit 1
fi
echo -e "${GREEN}✓ Backend is running${NC}"

# Check if frontend is running
if ! curl -s "${FRONTEND_URL}" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Frontend not running at ${FRONTEND_URL}${NC}"
    echo "   (Continuing with backend tests only)"
fi

# Check if agent is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 not found${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Step 2: Setting up test environment...${NC}"

# Generate keys if they don't exist
if [ ! -f "${KEYSTORE_DIR}/priv.key" ]; then
    echo "Generating test keys..."
    cd agent
    source venv/bin/activate 2>/dev/null || python3 -m venv venv && source venv/bin/activate
    pip install -q -r requirements.txt 2>/dev/null || true
    python -m agent.cli generate-key --keystore "${KEYSTORE_DIR}" || {
        echo -e "${YELLOW}Note: Keys may already exist${NC}"
    }
    cd ..
fi
echo -e "${GREEN}✓ Keys ready${NC}"

echo ""
echo -e "${BLUE}Step 3: Running agent scan...${NC}"

cd agent
source venv/bin/activate 2>/dev/null || python3 -m venv venv && source venv/bin/activate
pip install -q -r requirements.txt 2>/dev/null || true

test_step "Agent scan" python -m agent.cli scan "../${TEST_PROJECT}" \
    --output "${REPORT_FILE}" \
    --keystore "${KEYSTORE_DIR}" \
    --project-name "e2e-test-project"

if [ ! -f "${REPORT_FILE}" ]; then
    echo -e "${RED}✗ Report file not generated${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Report generated: ${REPORT_FILE}${NC}"
cd ..

echo ""
echo -e "${BLUE}Step 4: Testing backend verification...${NC}"

# Get public key
cd agent
source venv/bin/activate 2>/dev/null
PUBLIC_KEY=$(python -m agent.cli public-key --keystore "${KEYSTORE_DIR}" 2>/dev/null)
cd ..

if [ -z "$PUBLIC_KEY" ]; then
    echo -e "${RED}✗ Could not retrieve public key${NC}"
    exit 1
fi

# Verify report via backend
VERIFY_RESPONSE=$(curl -s -X POST "${BACKEND_URL}/verify-report" \
    -H "Content-Type: application/json" \
    -d @- <<EOF
{
    "report": $(cat "${REPORT_FILE}"),
    "public_key_hex": "${PUBLIC_KEY}"
}
EOF
)

if echo "$VERIFY_RESPONSE" | grep -q '"valid":true'; then
    echo -e "${GREEN}✓ Backend verification passed${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Backend verification failed${NC}"
    echo "Response: $VERIFY_RESPONSE"
    ((TESTS_FAILED++))
fi

echo ""
echo -e "${BLUE}Step 5: Testing attestation...${NC}"

# Create attestation
ATTEST_RESPONSE=$(curl -s -X POST "${BACKEND_URL}/attest" \
    -H "Content-Type: application/json" \
    -d @- <<EOF
{
    "merkle_root": $(cat "${REPORT_FILE}" | python3 -c "import sys, json; print(json.dumps(json.load(sys.stdin)['merkle_root']))"),
    "public_key_hex": "${PUBLIC_KEY}",
    "metadata": {
        "project_name": "e2e-test-project",
        "frameworks": ["SOC2", "ISO27001"]
    }
}
EOF
)

if echo "$ATTEST_RESPONSE" | grep -q '"attest_id"'; then
    echo -e "${GREEN}✓ Attestation created successfully${NC}"
    ((TESTS_PASSED++))
    ATTESTATION_ID=$(echo "$ATTEST_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('attest_id', ''))")
    echo "   Attestation ID: ${ATTESTATION_ID}"
elif echo "$ATTEST_RESPONSE" | grep -q '"status":"recorded"'; then
    echo -e "${GREEN}✓ Attestation created successfully${NC}"
    ((TESTS_PASSED++))
    ATTESTATION_ID=$(echo "$ATTEST_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('attest_id', ''))")
    echo "   Attestation ID: ${ATTESTATION_ID}"
else
    echo -e "${RED}✗ Attestation creation failed${NC}"
    echo "Response: $ATTEST_RESPONSE"
    ((TESTS_FAILED++))
fi

echo ""
echo -e "${BLUE}Step 6: Testing attestation retrieval...${NC}"

# Get attestations
ATTESTATIONS=$(curl -s "${BACKEND_URL}/api/attestations?limit=10")

if echo "$ATTESTATIONS" | grep -q '"id"'; then
    echo -e "${GREEN}✓ Attestations retrieved successfully${NC}"
    ((TESTS_PASSED++))
    ATTEST_COUNT=$(echo "$ATTESTATIONS" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total', 0))" 2>/dev/null || echo "0")
    echo "   Total attestations: ${ATTEST_COUNT}"
else
    echo -e "${YELLOW}⚠ Could not retrieve attestations${NC}"
    echo "Response: $ATTESTATIONS"
    ((TESTS_FAILED++))
fi

echo ""
echo "========================================="
echo -e "${BLUE}TEST SUMMARY${NC}"
echo "========================================="
echo -e "${GREEN}Tests Passed: ${TESTS_PASSED}${NC}"
echo -e "${RED}Tests Failed: ${TESTS_FAILED}${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review the report: ${REPORT_FILE}"
    echo "  2. Check attestations at: ${BACKEND_URL}/api/attestations"
    echo "  3. View frontend at: ${FRONTEND_URL}"
    exit 0
else
    echo ""
    echo -e "${RED}⚠ Some tests failed. Review the output above.${NC}"
    exit 1
fi


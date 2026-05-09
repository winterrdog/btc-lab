#!/bin/bash
# Bitcoin Core Coverage Report Generator
# Usage: ./generate_coverage.sh

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Bitcoin Core Coverage Report Generator ===${NC}\n"

# Check for required tools
echo "Checking prerequisites..."
command -v lcov >/dev/null 2>&1 || { 
    echo -e "${RED}Error: lcov is not installed${NC}"
    echo "Install with: sudo apt-get install lcov"
    exit 1
}
command -v genhtml >/dev/null 2>&1 || {
    echo -e "${RED}Error: genhtml is not installed${NC}"
    echo "Install with: sudo apt-get install lcov"
    exit 1
}
echo -e "${GREEN}✓ All prerequisites found${NC}\n"

# Step 1: Clean old data
echo -e "${YELLOW}[1/6] Cleaning old build and coverage data...${NC}"
rm -rf build/ coverage_report/ coverage*.info
echo -e "${GREEN}✓ Cleaned${NC}\n"

# Step 2: Configure CMake with Coverage flags
echo -e "${YELLOW}[2/6] Configuring CMake with Coverage build type...${NC}"
cmake -B build -DCMAKE_BUILD_TYPE=Coverage \
    -DBUILD_GUI=OFF \
    -DBUILD_BENCH=OFF \
    -DBUILD_FOR_FUZZING=OFF \
    -DBUILD_BITCOIN_WALLET=OFF \
    -DBUILD_BITCOIN_ZMQ=OFF \
    -DBUILD_BITCOIN_QT=OFF \
    -DBUILD_KERNEL_LIB=OFF \
    -DBUILD_TESTS=ON \
    -DBUILD_UTIL=ON \
    -DBUILD_TX=OFF
echo -e "${GREEN}✓ Configured${NC}\n"

# Step 3: Build
echo -e "${YELLOW}[3/6] Building Bitcoin Core with coverage instrumentation...${NC}"
cmake --build build -j $(nproc)
echo -e "${GREEN}✓ Built${NC}\n"

# Step 4: Run tests
echo -e "${YELLOW}[4/6] Running test suite...${NC}"
cd build
ctest --output-on-failure || {
    echo -e "${RED}Warning: Some tests failed, but continuing with coverage...${NC}"
}
cd ..
echo -e "${GREEN}✓ Tests completed${NC}\n"

# Step 5: Capture coverage data
echo -e "${YELLOW}[5/6] Capturing coverage data...${NC}"

# Try CMake's built-in cov target first
if cmake --build build --target cov 2>/dev/null; then
    echo -e "${GREEN}✓ Used CMake cov target${NC}"
    # Find where the report was generated
    if [ -d "build/coverage" ]; then
        mv build/coverage coverage_report
        echo -e "${GREEN}✓ Coverage report ready at: coverage_report/index.html${NC}\n"
        echo -e "${GREEN}=== DONE ===${NC}"
        echo "Open the report with:"
        echo "  firefox coverage_report/index.html"
        echo "  or"
        echo "  python3 -m http.server 8000 --directory coverage_report"
        exit 0
    fi
fi

# Fallback to manual lcov
echo "CMake cov target not available, using lcov manually..."

lcov --capture \
    --directory build \
    --output-file coverage_raw.info \
    --rc lcov_branch_coverage=1 \
    --rc geninfo_unexecuted_blocks=0 \
    --ignore-errors mismatch,empty,negative,unused,inconsistent,source

echo -e "${GREEN}✓ Coverage data captured${NC}\n"

# Step 6: Filter and generate HTML report
echo -e "${YELLOW}[6/6] Generating HTML coverage report...${NC}"

lcov --remove coverage_raw.info \
    '/usr/*' \
    '*/test/*' \
    '*/tests/*' \
    '*/depends/*' \
    '*/src/secp256k1/*' \
    '*/build/*' \
    --output-file coverage_filtered.info \
    --rc lcov_branch_coverage=1 \
    --rc geninfo_unexecuted_blocks=1 \
    --ignore-errors unused,unused,mismatch

genhtml coverage_filtered.info \
    --output-directory coverage_report \
    --branch-coverage \
    --function-coverage \
    --demangle-cpp \
    --legend \
    --title "Bitcoin Core Coverage Report" \
    --ignore-errors source

echo -e "${GREEN}✓ HTML report generated${NC}\n"

# Display summary
echo -e "${GREEN}=== Coverage Summary ===${NC}"
lcov --summary coverage_filtered.info \
    --rc lcov_branch_coverage=1 \
    --rc geninfo_unexecuted_blocks=1 \
    2>&1 | grep -E "(lines|functions|branches)"

echo ""
echo -e "${GREEN}=== DONE ===${NC}"
echo "Coverage report generated successfully!"
echo ""
echo "To view the report:"
echo "  1. Open in browser: firefox coverage_report/index.html"
echo "  2. Or start local server: python3 -m http.server 8000 --directory coverage_report"
echo "     Then visit: http://localhost:8000"
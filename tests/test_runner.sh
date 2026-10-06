#!/bin/bash
#
# Test Runner for FFmpeg h.264 Vulnerability Tests
# Runs vulnerable and patched test suites

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
VULNERABLE_BIN="$SCRIPT_DIR/vulnerable"
PATCHED_BIN="$SCRIPT_DIR/patched"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Compile test
compile_test() {
    local src_file=$1
    local out_file=$2
    local mode=$3

    print_status "Compiling: $(basename $src_file)"

    local flags="-Wall -Wextra -std=c99"

    case "$mode" in
        debug)
            flags="$flags -g -O0 -DDEBUG"
            ;;
        asan)
            flags="$flags -g -O0 -fsanitize=address -fsanitize=undefined"
            ;;
        *)
            flags="$flags -O2"
            ;;
    esac

    if gcc $flags -o "$out_file" "$src_file" 2>&1; then
        print_status "Compiled: $out_file"
        return 0
    else
        print_error "Compilation failed: $src_file"
        return 1
    fi
}

# Run test with error handling
run_test() {
    local bin_file=$1
    local name=$2
    local mode=$3

    print_status "Running: $name"

    local exit_code=0

    case "$mode" in
        asan)
            ASAN_OPTIONS="verbosity=0:halt_on_error=1:detect_leaks=0" \
                "$bin_file" 2>&1 || exit_code=$?
            ;;
        *)
            "$bin_file" 2>&1 || exit_code=$?
            ;;
    esac

    return $exit_code
}

# Parse command line
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --debug     Run with debug symbols"
    echo "  --asan      Run with AddressSanitizer"
    echo "  --verbose   Show detailed output"
    echo "  --clean     Clean test binaries"
    echo "  --help      Show this help message"
    echo ""
}

# Main test execution
main() {
    local mode="release"
    local verbose=0
    local clean_only=0

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --debug)
                mode="debug"
                ;;
            --asan)
                mode="asan"
                ;;
            --verbose)
                verbose=1
                ;;
            --clean)
                clean_only=1
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done

    # Clean operation
    if [ $clean_only -eq 1 ]; then
        print_header "Cleaning Test Artifacts"
        rm -f "$VULNERABLE_BIN" "$PATCHED_BIN"
        print_status "Cleaned"
        exit 0
    fi

    # Main test execution
    print_header "FFmpeg h.264 Vulnerability Test Suite"

    printf "Test Mode: ${BLUE}%s${NC}\n" "$mode"
    echo ""

    # Compile phase
    print_header "Compilation Phase"

    if ! compile_test "$SCRIPT_DIR/vulnerable.c" "$VULNERABLE_BIN" "$mode"; then
        print_error "Build phase failed"
        exit 1
    fi

    if ! compile_test "$SCRIPT_DIR/patched.c" "$PATCHED_BIN" "$mode"; then
        print_error "Build phase failed"
        exit 1
    fi

    # Execution phase
    print_header "Execution Phase"

    local test_results=()
    local pass_count=0
    local fail_count=0

    # Run vulnerable tests
    echo -e "${YELLOW}--- Vulnerable Code Path ---${NC}"
    if run_test "$VULNERABLE_BIN" "Vulnerable Code Tests" "$mode"; then
        test_results+=("PASS: Vulnerable tests")
        ((pass_count++))
    else
        test_results+=("FAIL: Vulnerable tests (exit code $?)")
        ((fail_count++))
    fi

    echo ""

    # Run patched tests
    echo -e "${YELLOW}--- Patched Code Path ---${NC}"
    if run_test "$PATCHED_BIN" "Patched Code Tests" "$mode"; then
        test_results+=("PASS: Patched tests")
        ((pass_count++))
    else
        test_results+=("FAIL: Patched tests (exit code $?)")
        ((fail_count++))
    fi

    # Results summary
    print_header "Test Results Summary"

    printf "Total test groups: %d\n" $((pass_count + fail_count))
    printf "Passed: %d\n" "$pass_count"
    printf "Failed: %d\n" "$fail_count"
    echo ""

    for result in "${test_results[@]}"; do
        if [[ "$result" == PASS* ]]; then
            echo -e "${GREEN}✓${NC} $result"
        else
            echo -e "${RED}✗${NC} $result"
        fi
    done

    echo ""

    # Final status
    if [ $fail_count -eq 0 ]; then
        print_header "Test Execution Successful"
        echo -e "${GREEN}All tests passed${NC}"
        return 0
    else
        print_header "Test Execution Failed"
        echo -e "${RED}Some tests failed${NC}"
        return 1
    fi
}

# Execute main
main "$@"

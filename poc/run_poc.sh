#!/bin/bash
#
# FFmpeg h.264 Vulnerability PoC Runner
#
# Automatically compiles and executes the proof of concept
# Handles different build configurations and sanitizers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$PROJECT_ROOT/src"
POC_DIR="$SCRIPT_DIR"

# Configuration
EXPLOIT_BIN="$POC_DIR/exploit"
LIB_PATH="$SRC_DIR/libvulnerable.a"
BUILD_MODE="release"  # or "debug", "asan"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
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

# Check requirements
check_requirements() {
    print_header "Checking Requirements"

    local missing=0

    if ! command -v gcc &> /dev/null; then
        print_error "gcc not found"
        missing=1
    else
        print_status "gcc found: $(gcc --version | head -1)"
    fi

    if ! command -v make &> /dev/null; then
        print_error "make not found"
        missing=1
    else
        print_status "make found"
    fi

    if [ $missing -eq 1 ]; then
        print_error "Missing required tools"
        return 1
    fi

    return 0
}

# Build the library
build_library() {
    print_header "Building Library"

    if [ ! -d "$SRC_DIR" ]; then
        print_error "Source directory not found: $SRC_DIR"
        return 1
    fi

    cd "$SRC_DIR"
    print_status "Building in: $SRC_DIR"

    case "$BUILD_MODE" in
        debug)
            print_status "Build mode: DEBUG (with symbols)"
            make clean && make debug
            ;;
        asan)
            print_status "Build mode: ASAN (AddressSanitizer)"
            make clean && make asan
            ;;
        *)
            print_status "Build mode: RELEASE (optimized)"
            make clean && make release
            ;;
    esac

    if [ ! -f "$LIB_PATH" ]; then
        print_error "Build failed - library not created: $LIB_PATH"
        return 1
    fi

    print_status "Library created: $LIB_PATH"
    return 0
}

# Compile exploit PoC
compile_exploit() {
    print_header "Compiling Exploit PoC"

    cd "$POC_DIR"

    local compile_flags="-Wall -Wextra -std=c99 -o $EXPLOIT_BIN"

    case "$BUILD_MODE" in
        debug)
            compile_flags="$compile_flags -g -O0 -DDEBUG"
            ;;
        asan)
            compile_flags="$compile_flags -g -O0 -fsanitize=address -fsanitize=undefined"
            ;;
        *)
            compile_flags="$compile_flags -O2"
            ;;
    esac

    print_status "Compiling: exploit.c"
    print_status "Compiler flags: $compile_flags"

    if gcc exploit.c $compile_flags -L"$SRC_DIR" -lvulnerable -lm 2>&1; then
        print_status "Compilation successful"
    else
        print_error "Compilation failed"
        return 1
    fi

    if [ ! -f "$EXPLOIT_BIN" ]; then
        print_error "Binary not created: $EXPLOIT_BIN"
        return 1
    fi

    print_status "Binary created: $EXPLOIT_BIN"
    print_status "Binary size: $(du -h "$EXPLOIT_BIN" | cut -f1)"

    return 0
}

# Run exploit PoC
run_exploit() {
    print_header "Running Exploit PoC"

    if [ ! -f "$EXPLOIT_BIN" ]; then
        print_error "Binary not found: $EXPLOIT_BIN"
        return 1
    fi

    print_status "Executing: $EXPLOIT_BIN"

    case "$BUILD_MODE" in
        asan)
            print_warning "ASAN enabled - memory safety checks active"
            ASAN_OPTIONS="verbosity=2:halt_on_error=1:detect_leaks=0" \
                "$EXPLOIT_BIN" --all
            ;;
        *)
            "$EXPLOIT_BIN" --all
            ;;
    esac

    local exit_code=$?

    case $exit_code in
        0)
            print_status "PoC executed successfully (exit code 0)"
            ;;
        1)
            print_warning "PoC exit code 1 - possible intentional test failure"
            ;;
        *)
            print_warning "PoC exit code: $exit_code"
            ;;
    esac

    return $exit_code
}

# Main execution
main() {
    echo ""
    echo "###########################################"
    echo "#  FFmpeg h.264 Vulnerability PoC Runner #"
    echo "###########################################"
    echo ""

    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --debug)
                BUILD_MODE="debug"
                print_status "Build mode set to: DEBUG"
                ;;
            --asan)
                BUILD_MODE="asan"
                print_status "Build mode set to: ASAN"
                ;;
            --release)
                BUILD_MODE="release"
                print_status "Build mode set to: RELEASE"
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --debug     Build with debug symbols"
                echo "  --asan      Build with AddressSanitizer"
                echo "  --release   Build release version (default)"
                echo "  --clean     Clean build artifacts"
                echo "  --help      Show this help message"
                echo ""
                exit 0
                ;;
            --clean)
                cd "$SRC_DIR"
                make clean
                rm -f "$EXPLOIT_BIN"
                print_status "Cleaned build artifacts"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done

    # Execute build pipeline
    if ! check_requirements; then
        print_error "Requirements check failed"
        exit 1
    fi

    if ! build_library; then
        print_error "Library build failed"
        exit 1
    fi

    if ! compile_exploit; then
        print_error "Exploit compilation failed"
        exit 1
    fi

    if ! run_exploit; then
        print_warning "PoC execution completed with warnings"
    fi

    print_header "PoC Execution Complete"

    echo ""
    echo "Results:"
    echo "  Library: $LIB_PATH"
    echo "  Binary:  $EXPLOIT_BIN"
    echo ""

    if [ "$BUILD_MODE" = "asan" ]; then
        echo "Memory Safety Report:"
        echo "  - AddressSanitizer enabled"
        echo "  - Watch for heap corruption warnings above"
        echo ""
    fi

    echo "###########################################"
    echo ""
}

# Execute main
main "$@"

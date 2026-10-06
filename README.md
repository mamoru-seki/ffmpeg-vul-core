# FFmpeg h.264 Slice Counter OOB Vulnerability Core

A minimal reproduction and analysis repository for the h.264 slice counter out-of-bounds (OOB) vulnerability in FFmpeg, discovered through automated security analysis.

## Overview

- **Vulnerability Type**: Slice Counter Buffer Overflow (CWE-787, CWE-90)
- **Affected Component**: FFmpeg h.264 parser (`h264_parse.c`)
- **Discovery Method**: Automated sourcehunt analysis (Phase B standard depth)
- **Status**: Analysis & verification in progress
- **Responsible Disclosure**: Private repository for research and analysis

## Vulnerability Details

The FFmpeg h.264 video decoder contains an out-of-bounds memory access vulnerability in the slice buffer counter management. When processing specially crafted H.264 streams, the decoder fails to properly validate slice count boundaries, leading to potential memory corruption.

See [VULNERABILITY.md](VULNERABILITY.md) for detailed technical analysis.

## Repository Structure

```
ffmpeg-vul-core/
├── README.md                    # Overview and usage guide
├── VULNERABILITY.md             # Detailed technical analysis
├── src/                        # Core vulnerability components
│   ├── h264_parse.c            # H.264 parser slice handling
│   ├── slice_buffer.c          # Slice counter management
│   ├── buffer_overflow.c       # OOB access implementation
│   └── Makefile                # Build configuration
├── poc/                        # Proof of Concept
│   ├── exploit.c               # PoC code
│   ├── poc.h264                # Test file (binary or generated)
│   └── run_poc.sh              # Automated PoC runner
├── tests/                      # Verification tests
│   ├── vulnerable.c            # Vulnerable code path test
│   ├── patched.c               # Patched code path test
│   └── test_runner.sh          # Test orchestration
├── analysis/                   # Security analysis
│   ├── cwe-analysis.md         # CWE-787/125/90 analysis
│   ├── dataflow.txt            # Source → Sink flow diagram
│   └── discovery-log.md        # Detection methodology
└── .github/
    └── workflows/
        └── verify-poc.yml      # CI/CD verification pipeline
```

## Quick Start

### Building

```bash
cd src
make clean
make
```

### Running PoC

```bash
cd poc
./run_poc.sh
```

Expected output shows memory access patterns and verification results.

### Running Tests

```bash
cd tests
./test_runner.sh
```

Compares vulnerable vs. patched code paths.

## Security Analysis

### CWE Classification

- **Primary**: CWE-787 (Out-of-bounds Write)
- **Secondary**: CWE-125 (Out-of-bounds Read)
- **Injection**: CWE-90 (Improper Neutralization of Special Elements)

### Dataflow

```
Packet Parser (untrusted input)
    ↓
Slice Count Extraction
    ↓
Buffer Allocation (insufficient bounds check)
    ↓
Slice Data Write
    ↓
Buffer Overflow (OOB access)
```

### Detection Points

- Slice counter validation in h264_parse.c
- Buffer size computation for slice storage
- Array access bounds checking

## Verification

This repository includes:

- Minimal reproducible test cases
- Vulnerable and patched code paths
- Automated CI pipeline for PoC verification
- Detailed analysis documentation

**Status**: Verification pending full PoC execution

## Responsible Disclosure

This repository is maintained under responsible disclosure principles:

1. **Private Repository**: Access limited to authorized security researchers
2. **Non-Executable by Default**: PoC components require explicit compilation
3. **Documentation Focus**: Emphasis on understanding over exploitation
4. **Vendor Coordination**: Following responsible disclosure timeline

### Usage Guidelines

- Use only for authorized security analysis and testing
- Do not deploy proof-of-concept in production environments
- Report findings through official vulnerability disclosure channels
- Coordinate with FFmpeg team for patches and CVE assignment

## Contributing

This is a private research repository. Contact repository maintainers for access and contribution guidelines.

## Related Resources

- FFmpeg Security: https://ffmpeg.org/security.html
- CWE-787: https://cwe.mitre.org/data/definitions/787.html
- CWE-125: https://cwe.mitre.org/data/definitions/125.html

## License

This analysis and code is provided for security research purposes only.
See repository license file for detailed terms.

---

**Last Updated**: 2026-10-06
**Discovery Method**: Automated sourcehunt (FFmpeg hunt, Phase B)

# Makefile for FFmpeg h.264 vulnerability analysis
# Compiles vulnerable and patched code versions

CC := gcc
CFLAGS := -Wall -Wextra -Wno-unused-parameter -std=c99 -fPIC
CFLAGS_DEBUG := $(CFLAGS) -g -O0 -DDEBUG
CFLAGS_ASAN := $(CFLAGS_DEBUG) -fsanitize=address -fsanitize=undefined
LDFLAGS := -lm
LDFLAGS_ASAN := $(LDFLAGS) -fsanitize=address -fsanitize=undefined

# Source files
SOURCES := h264_parse.c slice_buffer.c buffer_overflow.c
OBJECTS := $(SOURCES:.c=.o)
HEADERS := h264_parse.h slice_buffer.h buffer_overflow.h

# Output files
LIB := libvulnerable.a
LIB_PATCHED := libpatched.a

# Targets
.PHONY: all clean release debug asan help

all: release

help:
	@echo "FFmpeg h.264 Vulnerability Analysis Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build release version (default)"
	@echo "  release   - Build optimized release"
	@echo "  debug     - Build with debug symbols"
	@echo "  asan      - Build with AddressSanitizer"
	@echo "  clean     - Remove all build artifacts"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make debug  # Build with debug symbols"
	@echo "  make asan   # Build with memory sanitizer"

# Release build (default)
release: CFLAGS := -Wall -Wextra -std=c99 -O2 -fPIC
release: $(LIB)
	@echo "[RELEASE] Build complete: $(LIB)"

# Debug build
debug: CFLAGS := $(CFLAGS_DEBUG)
debug: $(LIB)
	@echo "[DEBUG] Build complete: $(LIB)"

# AddressSanitizer build
asan: CFLAGS := $(CFLAGS_ASAN)
asan: LDFLAGS := $(LDFLAGS_ASAN)
asan: $(LIB)
	@echo "[ASAN] Build complete: $(LIB)"
	@echo "[ASAN] Run with: ASAN_OPTIONS=verbosity=2:halt_on_error=1"

# Static library
$(LIB): $(OBJECTS)
	@echo "[AR] Creating library: $@"
	@ar rcs $@ $(OBJECTS)
	@echo "[AR] Done: $@"

# Object files
%.o: %.c %.h
	@echo "[CC] Compiling: $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Without header dependency (for files that might not have headers)
%.o: %.c
	@echo "[CC] Compiling: $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "[CLEAN] Removing build artifacts..."
	@rm -f *.o *.a *.so core core.* *~
	@echo "[CLEAN] Done"

# Display build information
info:
	@echo "Build Configuration:"
	@echo "  Compiler: $(CC)"
	@echo "  Flags: $(CFLAGS)"
	@echo "  Linker: $(LDFLAGS)"
	@echo "  Sources: $(SOURCES)"
	@echo "  Library: $(LIB)"

# Detailed help with examples
examples:
	@echo "Build Examples:"
	@echo ""
	@echo "1. Release build (optimized):"
	@echo "   make clean && make release"
	@echo ""
	@echo "2. Debug build (with symbols):"
	@echo "   make clean && make debug"
	@echo ""
	@echo "3. Memory sanitizer build:"
	@echo "   make clean && make asan"
	@echo ""
	@echo "4. Compile and link against library:"
	@echo "   gcc -c exploit.c -o exploit.o"
	@echo "   gcc exploit.o -L. -lvulnerable -o exploit"
	@echo ""
	@echo "5. Run with debug output:"
	@echo "   CFLAGS=\"-DDEBUG -g\" make clean && make"

.PHONY: info examples

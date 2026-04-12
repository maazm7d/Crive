# =============================================================================
# Makefile - crive password recovery framework
# Targets: Linux, Android/Termux
# Compiler: GCC or Clang, C11
# =============================================================================

# -----------------------------------------------------------------------------
# PROJECT METADATA
# -----------------------------------------------------------------------------
PROJECT         := crive
VERSION_MAJOR   := 1
VERSION_MINOR   := 0
VERSION_PATCH   := 0
VERSION         := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
DESCRIPTION     := Archive Password Recovery Framework

# -----------------------------------------------------------------------------
# DIRECTORIES
# -----------------------------------------------------------------------------
SRCDIR          := .
OBJDIR          := build/obj
BINDIR          := build/bin
DEPDIR          := build/dep
TESTDIR         := tests
DISTDIR         := dist

# -----------------------------------------------------------------------------
# SOURCE FILES
# -----------------------------------------------------------------------------
SRCS            := utils.c \
                   archive.c \
                   attacks.c \
                   engine.c \
                   main.c

OBJS            := $(SRCS:%.c=$(OBJDIR)/%.o)
DEPS            := $(SRCS:%.c=$(DEPDIR)/%.d)
TARGET          := $(BINDIR)/$(PROJECT)

# -----------------------------------------------------------------------------
# COMPILER DETECTION
# -----------------------------------------------------------------------------
# Prefer clang if available, fallback to gcc
ifeq ($(CC),cc)
  CC_CLANG := $(shell command -v clang 2>/dev/null)
  ifneq ($(CC_CLANG),)
    CC := clang
  else
    CC := gcc
  endif
endif

# Detect compiler family
CC_IS_CLANG := $(shell $(CC) --version 2>&1 | grep -c clang)
CC_IS_GCC   := $(shell $(CC) --version 2>&1 | grep -c gcc)

# -----------------------------------------------------------------------------
# PLATFORM DETECTION
# -----------------------------------------------------------------------------
UNAME_S         := $(shell uname -s)
UNAME_M         := $(shell uname -m)

# Android/Termux detection
IS_ANDROID      := 0
ifneq ($(wildcard /system/build.prop),)
  IS_ANDROID    := 1
endif
ifneq ($(PREFIX),)
  ifneq ($(findstring com.termux,$(PREFIX)),)
    IS_ANDROID  := 1
  endif
endif
ifneq ($(ANDROID_ROOT),)
  IS_ANDROID    := 1
endif

# Architecture
IS_ARM64        := 0
IS_ARM32        := 0
IS_X86_64       := 0
IS_X86          := 0

ifeq ($(UNAME_M),aarch64)
  IS_ARM64      := 1
endif
ifeq ($(UNAME_M),arm)
  IS_ARM32      := 1
endif
ifeq ($(UNAME_M),x86_64)
  IS_X86_64     := 1
endif
ifeq ($(UNAME_M),i686)
  IS_X86        := 1
endif

# -----------------------------------------------------------------------------
# BASE FLAGS
# -----------------------------------------------------------------------------
CSTD            := -std=c11
CWARN           := -Wall \
                   -Wextra \
                   -Wshadow \
                   -Wstrict-prototypes \
                   -Wmissing-prototypes \
                   -Wformat=2 \
                   -Wformat-security \
                   -Wno-unused-parameter \
                   -Wno-unused-function \
                   -Wno-missing-field-initializers \
                   -Wundef \
                   -Wpointer-arith \
                   -Wcast-align \
                   -Wwrite-strings \
                   -Wno-missing-prototypes \
                   -Wno-strict-prototypes \
                   -Wno-date-time \
                   -Wno-unused-macros \
                   -Wno-sign-conversion \
                   -Wno-bad-function-cast

# Clang-specific warnings (replaced block)
ifeq ($(CC_IS_CLANG),1)
  CWARN         += -Weverything \
                   -Wno-unsafe-buffer-usage \
                   -Wno-error=unsafe-buffer-usage \
                   -Wno-cast-align \
                   -Wno-sign-conversion \
                   -Wno-unused-macros \
                   -Wno-padded \
                   -Wno-covered-switch-default \
                   -Wno-disabled-macro-expansion \
                   -Wno-documentation \
                   -Wno-documentation-unknown-command \
                   -Wno-reserved-id-macro \
                   -Wno-gnu-zero-variadic-macro-arguments \
                   -Wno-c99-extensions \
                   -Wno-declaration-after-statement \
                   -Wno-pre-c11-compat
endif

CDEFS           := -D_GNU_SOURCE \
                   -D_POSIX_C_SOURCE=200809L \
                   -DCRIVE_VERSION_MAJOR=$(VERSION_MAJOR) \
                   -DCRIVE_VERSION_MINOR=$(VERSION_MINOR) \
                   -DCRIVE_VERSION_PATCH=$(VERSION_PATCH) \
                   -DCRIVE_VERSION_STR=\"$(VERSION)\"

# Platform-specific defs
ifeq ($(IS_ANDROID),1)
  CDEFS         += -D__ANDROID__=1
  $(info [Platform] Android/Termux detected)
else
  $(info [Platform] $(UNAME_S) $(UNAME_M))
endif

# -----------------------------------------------------------------------------
# DEPENDENCY GENERATION
# -----------------------------------------------------------------------------
DEPFLAGS        = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

# -----------------------------------------------------------------------------
# BUILD PROFILES
# -----------------------------------------------------------------------------

# Default: release
BUILD_PROFILE   ?= release

# --- release ---
ifeq ($(BUILD_PROFILE),release)
  OPT_FLAGS     := -O3 \
                   -funroll-loops \
                   -fomit-frame-pointer \
                   -finline-functions \
                   -fstrict-aliasing \
                   -fno-plt
  CDEFS         += -DNDEBUG
  STRIP_TARGET  := 1
endif

# --- debug ---
ifeq ($(BUILD_PROFILE),debug)
  OPT_FLAGS     := -O0 -g3 -ggdb3
  CDEFS         += -DDEBUG=1 -DCRIVE_DEBUG
  STRIP_TARGET  := 0
  CWARN         += -fsanitize=address,undefined
  LDFLAGS_EXTRA += -fsanitize=address,undefined
endif

# --- asan ---
ifeq ($(BUILD_PROFILE),asan)
  OPT_FLAGS     := -O1 -g3
  CDEFS         += -DDEBUG=1
  CWARN         += -fsanitize=address,undefined,leak
  LDFLAGS_EXTRA += -fsanitize=address,undefined,leak
  STRIP_TARGET  := 0
endif

# --- profile ---
ifeq ($(BUILD_PROFILE),profile)
  OPT_FLAGS     := -O2 -pg -g
  CDEFS         += -DNDEBUG
  STRIP_TARGET  := 0
endif

# --- selftest ---
ifeq ($(BUILD_PROFILE),selftest)
  OPT_FLAGS     := -O2 -g
  CDEFS         += -DCRIVE_SELFTEST=1
  STRIP_TARGET  := 0
endif

# Default OPT_FLAGS if profile not matched
OPT_FLAGS       ?= -O2

# -----------------------------------------------------------------------------
# ARCHITECTURE-SPECIFIC OPTIMIZATIONS
# -----------------------------------------------------------------------------
ARCH_FLAGS      :=

ifeq ($(IS_X86_64),1)
  ifeq ($(BUILD_PROFILE),release)
    # Try to auto-detect best arch, fallback to generic
    NATIVE_MARCH := $(shell $(CC) -march=native -Q --help=target 2>/dev/null \
                    | grep '\-march=' | head -1 | awk '{print $$2}')
    ifneq ($(NATIVE_MARCH),)
      ARCH_FLAGS  += -march=native -mtune=native
    else
      ARCH_FLAGS  += -march=x86-64 -mtune=generic
    endif
    ARCH_FLAGS    += -msse4.2 -maes
  else
    ARCH_FLAGS    += -march=x86-64
  endif
endif

ifeq ($(IS_ARM64),1)
  ifeq ($(BUILD_PROFILE),release)
    # ARMv8 with crypto extensions (AES hardware)
    ARCH_FLAGS    += -march=armv8-a+crypto
  else
    ARCH_FLAGS    += -march=armv8-a
  endif
  # Enable NEON
  ARCH_FLAGS      += -ftree-vectorize
endif

ifeq ($(IS_ARM32),1)
  ifeq ($(BUILD_PROFILE),release)
    ARCH_FLAGS    += -march=armv7-a -mfpu=neon -mfloat-abi=softfp
  else
    ARCH_FLAGS    += -march=armv7-a
  endif
endif

# Termux / Android specific arch tuning
ifeq ($(IS_ANDROID),1)
  ifeq ($(IS_ARM64),1)
    ARCH_FLAGS    := -march=armv8-a+crypto -mtune=cortex-a55
  endif
  ifeq ($(IS_ARM32),1)
    ARCH_FLAGS    := -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=softfp
  endif
endif

# -----------------------------------------------------------------------------
# LINKER FLAGS
# -----------------------------------------------------------------------------
LDFLAGS         := -lpthread \
                   -lm \
                   $(LDFLAGS_EXTRA)

# On non-Android Linux, use -ldl if needed
ifneq ($(IS_ANDROID),1)
  LDFLAGS       += -ldl
endif

# Use gold or lld linker if available (faster link)
ifeq ($(IS_ANDROID),0)
  LLD_AVAIL     := $(shell command -v ld.lld 2>/dev/null)
  ifneq ($(LLD_AVAIL),)
    LDFLAGS     += -fuse-ld=lld
  else
    GOLD_AVAIL  := $(shell command -v ld.gold 2>/dev/null)
    ifneq ($(GOLD_AVAIL),)
      LDFLAGS   += -fuse-ld=gold
    endif
  endif
endif

# Link-time optimization (release builds only, non-debug)
ifeq ($(BUILD_PROFILE),release)
  ifeq ($(CC_IS_GCC),1)
    LTO_FLAGS   := -flto=$(shell nproc 2>/dev/null || echo 1)
  else
    LTO_FLAGS   := -flto=thin
  endif
  OPT_FLAGS     += $(LTO_FLAGS)
  LDFLAGS       += $(LTO_FLAGS)
endif

# Security hardening flags (release)
ifeq ($(BUILD_PROFILE),release)
  HARDEN_FLAGS  := -fstack-protector-strong \
                   -D_FORTIFY_SOURCE=2 \
                   -fPIE
  ifeq ($(IS_ANDROID),0)
    HARDEN_FLAGS += -Wl,-z,relro \
                    -Wl,-z,now \
                    -Wl,-z,noexecstack \
                    -pie
  endif
endif

HARDEN_FLAGS    ?=

# -----------------------------------------------------------------------------
# FINAL CFLAGS ASSEMBLY
# -----------------------------------------------------------------------------
CFLAGS          := $(CSTD) \
                   $(CWARN) \
                   $(CDEFS) \
                   $(OPT_FLAGS) \
                   $(ARCH_FLAGS) \
                   $(HARDEN_FLAGS) \
                   -pipe

# Include directory
CFLAGS          += -I$(SRCDIR)

# -----------------------------------------------------------------------------
# UTILITY PROGRAMS
# -----------------------------------------------------------------------------
STRIP           := strip
MKDIR           := mkdir -p
RM              := rm -f
RMDIR           := rm -rf
INSTALL         := install
CP              := cp
TAR             := tar
FIND            := find
GREP            := grep

# Optional: ccache for faster rebuilds
CCACHE          := $(shell command -v ccache 2>/dev/null)
ifneq ($(CCACHE),)
  CC            := $(CCACHE) $(CC)
  $(info [Build] ccache enabled)
endif

# -----------------------------------------------------------------------------
# TARGETS
# -----------------------------------------------------------------------------

.PHONY: all clean distclean install uninstall \
        debug release asan profile selftest \
        check test bench info version \
        help strip-binary size deps \
        format lint termux dist

# Default target
all: $(TARGET)

# Build profiles as targets
release:
	$(MAKE) BUILD_PROFILE=release all

debug:
	$(MAKE) BUILD_PROFILE=debug all

asan:
	$(MAKE) BUILD_PROFILE=asan all

profile:
	$(MAKE) BUILD_PROFILE=profile all

selftest:
	$(MAKE) BUILD_PROFILE=selftest all
	@echo ""
	@echo "Running self-tests..."
	$(TARGET) --benchmark --no-progress 2>/dev/null || true

# -----------------------------------------------------------------------------
# DIRECTORY CREATION
# -----------------------------------------------------------------------------
$(OBJDIR) $(BINDIR) $(DEPDIR):
	@$(MKDIR) $@

# -----------------------------------------------------------------------------
# COMPILATION RULE
# -----------------------------------------------------------------------------
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR) $(DEPDIR)
	@echo "  CC    $<"
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

# -----------------------------------------------------------------------------
# LINK RULE
# -----------------------------------------------------------------------------
$(TARGET): $(OBJS) | $(BINDIR)
	@echo "  LD    $@"
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
ifeq ($(STRIP_TARGET),1)
	@echo "  STRIP $@"
	$(STRIP) --strip-all $@
endif
	@echo ""
	@echo "  Built: $@ [$(BUILD_PROFILE)]"
	@ls -lh $@

# -----------------------------------------------------------------------------
# DEPENDENCY INCLUSION
# -----------------------------------------------------------------------------
-include $(DEPS)

# -----------------------------------------------------------------------------
# CLEAN TARGETS
# -----------------------------------------------------------------------------
clean:
	@echo "  CLEAN $(OBJDIR) $(BINDIR) $(DEPDIR)"
	$(RMDIR) $(OBJDIR) $(BINDIR) $(DEPDIR)

distclean: clean
	@echo "  DISTCLEAN build/ $(DISTDIR)/"
	$(RMDIR) build/
	$(RMDIR) $(DISTDIR)/

# -----------------------------------------------------------------------------
# INSTALL / UNINSTALL
# -----------------------------------------------------------------------------
PREFIX          ?= /usr/local
BINDIR_INST     := $(DESTDIR)$(PREFIX)/bin
MANDIR          := $(DESTDIR)$(PREFIX)/share/man/man1

install: all
	@echo "  INSTALL $(TARGET) -> $(BINDIR_INST)/$(PROJECT)"
	$(MKDIR) $(BINDIR_INST)
	$(INSTALL) -m 755 $(TARGET) $(BINDIR_INST)/$(PROJECT)
	@echo "  Installed: $(BINDIR_INST)/$(PROJECT)"

uninstall:
	@echo "  UNINSTALL $(BINDIR_INST)/$(PROJECT)"
	$(RM) $(BINDIR_INST)/$(PROJECT)

# Termux-specific install
termux-install: all
	@echo "  INSTALL for Termux"
	$(MKDIR) $(PREFIX)/bin
	$(INSTALL) -m 755 $(TARGET) $(PREFIX)/bin/$(PROJECT)
	@echo "  Installed: $(PREFIX)/bin/$(PROJECT)"

# -----------------------------------------------------------------------------
# TERMUX BUILD TARGET
# Helper target for building in Termux environment
# -----------------------------------------------------------------------------
termux:
	@echo "Building for Termux/Android..."
	@echo "Prefix: $(PREFIX)"
	$(MAKE) BUILD_PROFILE=release \
	        IS_ANDROID=1 \
	        CC=gcc \
	        all
	@echo ""
	@echo "To install: make termux-install"

# -----------------------------------------------------------------------------
# STRIP BINARY
# -----------------------------------------------------------------------------
strip-binary: $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	@echo "Stripped: $(TARGET)"
	@ls -lh $(TARGET)

# -----------------------------------------------------------------------------
# SIZE ANALYSIS
# -----------------------------------------------------------------------------
size: $(TARGET)
	@echo ""
	@echo "Binary size analysis:"
	@ls -lh $(TARGET)
	@echo ""
	@if command -v size >/dev/null 2>&1; then \
	    size $(TARGET); \
	fi
	@echo ""
	@if command -v nm >/dev/null 2>&1; then \
	    echo "Top 20 symbols by size:"; \
	    nm --size-sort -S $(TARGET) 2>/dev/null \
	        | tail -20 \
	        | awk '{print $$2, $$4}' \
	        | sort -rn \
	        | head -20; \
	fi

# -----------------------------------------------------------------------------
# BENCHMARK TARGET
# -----------------------------------------------------------------------------
bench: all
	@echo ""
	@echo "Running benchmark (10 seconds)..."
	$(TARGET) --benchmark --threads $(shell nproc 2>/dev/null || echo 4)

# Short benchmark
bench-quick: all
	$(TARGET) --benchmark --benchmark-duration 3 \
	          --threads $(shell nproc 2>/dev/null || echo 4) \
	          --no-color

# -----------------------------------------------------------------------------
# TEST TARGETS
# -----------------------------------------------------------------------------

# Create test archives if they don't exist
$(TESTDIR):
	@$(MKDIR) $(TESTDIR)

# Create test ZIP with password "test123"
$(TESTDIR)/test.zip: | $(TESTDIR)
	@echo "Creating test ZIP archive..."
	@if command -v zip >/dev/null 2>&1; then \
	    echo "secret content" > /tmp/crive_test_content.txt; \
	    zip -j -P "test123" $@ /tmp/crive_test_content.txt; \
	    rm -f /tmp/crive_test_content.txt; \
	    echo "Created: $@"; \
	else \
	    echo "WARNING: 'zip' not found - cannot create test archive"; \
	    touch $@; \
	fi

# Create test 7z with password "test123"
$(TESTDIR)/test.7z: | $(TESTDIR)
	@echo "Creating test 7Z archive..."
	@if command -v 7z >/dev/null 2>&1; then \
	    echo "secret content" > /tmp/crive_test_content.txt; \
	    7z a -p"test123" -mhe=on $@ /tmp/crive_test_content.txt >/dev/null 2>&1; \
	    rm -f /tmp/crive_test_content.txt; \
	    echo "Created: $@"; \
	elif command -v 7za >/dev/null 2>&1; then \
	    echo "secret content" > /tmp/crive_test_content.txt; \
	    7za a -p"test123" -mhe=on $@ /tmp/crive_test_content.txt >/dev/null 2>&1; \
	    rm -f /tmp/crive_test_content.txt; \
	    echo "Created: $@"; \
	else \
	    echo "WARNING: '7z'/'7za' not found - cannot create test 7Z archive"; \
	    touch $@; \
	fi

# Create test wordlist
$(TESTDIR)/wordlist.txt: | $(TESTDIR)
	@echo "Creating test wordlist..."
	@printf 'password\n123456\ntest123\nqwerty\nletmein\ndragon\nadmin\n' > $@
	@echo "Created: $@"

# Full test suite
test: all $(TESTDIR)/test.zip $(TESTDIR)/test.7z $(TESTDIR)/wordlist.txt
	@echo ""
	@echo "============================================"
	@echo " Running crive test suite"
	@echo "============================================"
	@PASS=0; FAIL=0; \
	\
	echo ""; \
	echo "[TEST 1] ZIP dictionary attack (should find 'test123')"; \
	if $(TARGET) $(TESTDIR)/test.zip \
	    --wordlist $(TESTDIR)/wordlist.txt \
	    --threads 2 \
	    --no-color \
	    --no-progress \
	    --quiet 2>/dev/null; then \
	    echo "  PASS: ZIP dictionary attack"; PASS=$$((PASS+1)); \
	else \
	    echo "  FAIL: ZIP dictionary attack"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "[TEST 2] ZIP brute-force attack (min=7 max=7 charset=lower+digits)"; \
	if $(TARGET) $(TESTDIR)/test.zip \
	    --bruteforce \
	    --min 7 --max 7 \
	    --charset lower+digits \
	    --threads 2 \
	    --no-color \
	    --no-progress \
	    --quiet 2>/dev/null; then \
	    echo "  PASS: ZIP brute-force attack"; PASS=$$((PASS+1)); \
	else \
	    echo "  FAIL: ZIP brute-force attack"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "[TEST 3] ZIP mask attack (?l?l?l?d?d?d?d = test?????)"; \
	if $(TARGET) $(TESTDIR)/test.zip \
	    --mask '?l?l?l?l?d?d?d' \
	    --threads 2 \
	    --no-color \
	    --no-progress \
	    --quiet 2>/dev/null; then \
	    echo "  PASS: ZIP mask attack"; PASS=$$((PASS+1)); \
	else \
	    echo "  FAIL: ZIP mask attack"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "[TEST 4] ZIP rule-based attack"; \
	if $(TARGET) $(TESTDIR)/test.zip \
	    --wordlist $(TESTDIR)/wordlist.txt \
	    --rules \
	    --threads 2 \
	    --no-color \
	    --no-progress \
	    --quiet 2>/dev/null; then \
	    echo "  PASS: ZIP rule attack"; PASS=$$((PASS+1)); \
	else \
	    echo "  FAIL: ZIP rule attack"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "[TEST 5] ZIP hybrid attack"; \
	if $(TARGET) $(TESTDIR)/test.zip \
	    --wordlist $(TESTDIR)/wordlist.txt \
	    --hybrid \
	    --threads 2 \
	    --no-color \
	    --no-progress \
	    --quiet 2>/dev/null; then \
	    echo "  PASS: ZIP hybrid attack"; PASS=$$((PASS+1)); \
	else \
	    echo "  FAIL: ZIP hybrid attack"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "[TEST 6] Benchmark mode"; \
	if $(TARGET) --benchmark \
	    --benchmark-duration 2 \
	    --threads 1 \
	    --no-color \
	    --no-progress 2>/dev/null; then \
	    echo "  PASS: Benchmark"; PASS=$$((PASS+1)); \
	else \
	    echo "  FAIL: Benchmark"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "============================================"; \
	echo " Results: $$PASS passed, $$FAIL failed"; \
	echo "============================================"; \
	echo ""; \
	[ $$FAIL -eq 0 ]

# Quick smoke test
check: all $(TESTDIR)/wordlist.txt
	@echo "Running smoke test..."
	$(TARGET) --benchmark \
	          --benchmark-duration 1 \
	          --threads 1 \
	          --no-color \
	          --no-progress
	@echo "Smoke test passed."

# -----------------------------------------------------------------------------
# DEPENDENCY CHECK
# -----------------------------------------------------------------------------
deps:
	@echo "Checking dependencies..."
	@echo ""
	@# Required
	@echo "Required:"
	@command -v $(CC)      >/dev/null 2>&1 && echo "  [OK] $(CC)" \
	                                       || echo "  [MISSING] C compiler"
	@command -v make       >/dev/null 2>&1 && echo "  [OK] make" \
	                                       || echo "  [MISSING] make"
	@# Optional tools
	@echo ""
	@echo "Optional:"
	@command -v zip        >/dev/null 2>&1 && echo "  [OK] zip (test archive creation)" \
	                                       || echo "  [-] zip (not found - tests limited)"
	@command -v 7z         >/dev/null 2>&1 && echo "  [OK] 7z  (test archive creation)" \
	                                       || echo "  [-] 7z  (not found - tests limited)"
	@command -v 7za        >/dev/null 2>&1 && echo "  [OK] 7za (test archive creation)" \
	                                       || true
	@command -v ccache     >/dev/null 2>&1 && echo "  [OK] ccache (build cache)" \
	                                       || echo "  [-] ccache (not found)"
	@command -v clang      >/dev/null 2>&1 && echo "  [OK] clang" \
	                                       || echo "  [-] clang (not found)"
	@command -v gdb        >/dev/null 2>&1 && echo "  [OK] gdb" \
	                                       || echo "  [-] gdb (not found)"
	@command -v valgrind   >/dev/null 2>&1 && echo "  [OK] valgrind" \
	                                       || echo "  [-] valgrind (not found)"
	@command -v strip      >/dev/null 2>&1 && echo "  [OK] strip" \
	                                       || echo "  [-] strip"
	@echo ""

# -----------------------------------------------------------------------------
# LINT / FORMAT
# -----------------------------------------------------------------------------
lint:
	@echo "Running lint checks..."
	@if command -v cppcheck >/dev/null 2>&1; then \
	    cppcheck --enable=all \
	             --std=c11 \
	             --suppress=missingIncludeSystem \
	             --suppress=unusedFunction \
	             --quiet \
	             $(SRCS); \
	    echo "cppcheck done."; \
	else \
	    echo "cppcheck not found - skipping"; \
	fi
	@if command -v clang-tidy >/dev/null 2>&1; then \
	    clang-tidy $(SRCS) -- $(CSTD) $(CDEFS) -I$(SRCDIR) 2>/dev/null | head -50; \
	else \
	    echo "clang-tidy not found - skipping"; \
	fi

format:
	@echo "Formatting source files..."
	@if command -v clang-format >/dev/null 2>&1; then \
	    for f in $(SRCS); do \
	        clang-format -i --style="{BasedOnStyle: LLVM, IndentWidth: 4, \
	            ColumnLimit: 80}" $$f; \
	        echo "  Formatted: $$f"; \
	    done; \
	else \
	    echo "clang-format not found"; \
	fi

# -----------------------------------------------------------------------------
# VALGRIND TARGET
# -----------------------------------------------------------------------------
valgrind: debug $(TESTDIR)/test.zip $(TESTDIR)/wordlist.txt
	@echo "Running under valgrind..."
	valgrind \
	    --leak-check=full \
	    --show-leak-kinds=all \
	    --track-origins=yes \
	    --error-exitcode=1 \
	    --suppressions=/dev/null \
	    $(TARGET) \
	    $(TESTDIR)/test.zip \
	    --wordlist $(TESTDIR)/wordlist.txt \
	    --threads 1 \
	    --no-color \
	    --no-progress \
	    --quiet \
	    2>&1 | head -100

# -----------------------------------------------------------------------------
# GDB TARGET
# -----------------------------------------------------------------------------
gdb: debug $(TESTDIR)/test.zip $(TESTDIR)/wordlist.txt
	gdb -q \
	    --args $(TARGET) \
	    $(TESTDIR)/test.zip \
	    --wordlist $(TESTDIR)/wordlist.txt \
	    --threads 1 \
	    --no-color \
	    --no-progress

# -----------------------------------------------------------------------------
# PROFILING
# -----------------------------------------------------------------------------
gprof: profile $(TESTDIR)/test.zip $(TESTDIR)/wordlist.txt
	@echo "Running profiled binary..."
	$(TARGET) \
	    $(TESTDIR)/test.zip \
	    --wordlist $(TESTDIR)/wordlist.txt \
	    --threads 1 \
	    --no-color \
	    --no-progress \
	    --quiet 2>/dev/null || true
	@echo "Generating profile report..."
	@if [ -f gmon.out ]; then \
	    gprof $(TARGET) gmon.out > profile_report.txt; \
	    echo "Report: profile_report.txt"; \
	    head -50 profile_report.txt; \
	else \
	    echo "gmon.out not found"; \
	fi

# -----------------------------------------------------------------------------
# DISTRIBUTION PACKAGE
# -----------------------------------------------------------------------------
dist: release
	@echo "Creating distribution package..."
	$(MKDIR) $(DISTDIR)
	$(CP) $(TARGET) $(DISTDIR)/$(PROJECT)-$(VERSION)-$(UNAME_M)
	@if command -v upx >/dev/null 2>&1; then \
	    upx --best --lzma $(DISTDIR)/$(PROJECT)-$(VERSION)-$(UNAME_M) \
	    && echo "  UPX compressed"; \
	else \
	    echo "  (upx not available - skipping compression)"; \
	fi
	$(STRIP) --strip-all $(DISTDIR)/$(PROJECT)-$(VERSION)-$(UNAME_M) || true
	@ls -lh $(DISTDIR)/
	@echo "Distribution: $(DISTDIR)/$(PROJECT)-$(VERSION)-$(UNAME_M)"

# Source distribution
dist-src:
	@echo "Creating source distribution..."
	$(MKDIR) $(DISTDIR)
	$(TAR) --transform "s,^,$(PROJECT)-$(VERSION)/," \
	       -czf $(DISTDIR)/$(PROJECT)-$(VERSION)-src.tar.gz \
	       $(SRCS) Makefile README.md 2>/dev/null || \
	$(TAR) -czf $(DISTDIR)/$(PROJECT)-$(VERSION)-src.tar.gz \
	       --prefix=$(PROJECT)-$(VERSION)/ \
	       $(SRCS) Makefile
	@ls -lh $(DISTDIR)/$(PROJECT)-$(VERSION)-src.tar.gz

# -----------------------------------------------------------------------------
# INFO TARGET
# -----------------------------------------------------------------------------
info:
	@echo ""
	@echo "============================================"
	@echo " $(PROJECT) v$(VERSION) Build Information"
	@echo "============================================"
	@echo " CC:           $(CC)"
	@echo " CFLAGS:       $(CFLAGS)"
	@echo " LDFLAGS:      $(LDFLAGS)"
	@echo " Build Profile:$(BUILD_PROFILE)"
	@echo " Platform:     $(UNAME_S) $(UNAME_M)"
	@echo " Android:      $(IS_ANDROID)"
	@echo " ARM64:        $(IS_ARM64)"
	@echo " ARM32:        $(IS_ARM32)"
	@echo " x86_64:       $(IS_X86_64)"
	@echo " Sources:      $(SRCS)"
	@echo " Target:       $(TARGET)"
	@echo " Obj Dir:      $(OBJDIR)"
	@echo "============================================"
	@echo ""

# -----------------------------------------------------------------------------
# VERSION TARGET
# -----------------------------------------------------------------------------
version:
	@echo "$(PROJECT) v$(VERSION)"

# -----------------------------------------------------------------------------
# HELP TARGET
# -----------------------------------------------------------------------------
help:
	@echo ""
	@echo "$(PROJECT) v$(VERSION) - Build Targets"
	@echo ""
	@echo "Build profiles:"
	@echo "  make                   Build with default (release) profile"
	@echo "  make release           Optimized release build (O3 + LTO)"
	@echo "  make debug             Debug build (O0 + symbols + sanitizers)"
	@echo "  make asan              Address sanitizer build"
	@echo "  make profile           Profiling build (gprof)"
	@echo "  make selftest          Self-test build"
	@echo ""
	@echo "Testing:"
	@echo "  make test              Run full test suite"
	@echo "  make check             Quick smoke test"
	@echo "  make bench             Run benchmark (10 seconds)"
	@echo "  make bench-quick       Quick 3-second benchmark"
	@echo "  make valgrind          Run under valgrind"
	@echo ""
	@echo "Installation:"
	@echo "  make install           Install to $(PREFIX)/bin"
	@echo "  make uninstall         Remove from $(PREFIX)/bin"
	@echo "  make termux            Build for Termux/Android"
	@echo "  make termux-install    Install in Termux environment"
	@echo ""
	@echo "Packaging:"
	@echo "  make dist              Create binary distribution"
	@echo "  make dist-src          Create source tarball"
	@echo ""
	@echo "Development:"
	@echo "  make lint              Run cppcheck/clang-tidy"
	@echo "  make format            Run clang-format"
	@echo "  make gdb               Debug in GDB"
	@echo "  make gprof             Profile with gprof"
	@echo "  make size              Analyze binary size"
	@echo "  make deps              Check tool dependencies"
	@echo ""
	@echo "Info:"
	@echo "  make info              Show build configuration"
	@echo "  make version           Show version string"
	@echo "  make help              Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  CC=<compiler>          Override compiler (gcc/clang)"
	@echo "  PREFIX=<path>          Install prefix [/usr/local]"
	@echo "  BUILD_PROFILE=<p>      Build profile [release]"
	@echo "  DESTDIR=<dir>          Staging directory for install"
	@echo ""
	@echo "Examples:"
	@echo "  make CC=clang release"
	@echo "  make debug"
	@echo "  make install PREFIX=~/.local"
	@echo "  make termux && make termux-install"
	@echo ""

# -----------------------------------------------------------------------------
# SPECIAL TARGETS
# -----------------------------------------------------------------------------

# Rebuild everything from scratch
rebuild: distclean all

# Count lines of code
loc:
	@echo "Lines of code:"
	@wc -l $(SRCS) Makefile | sort -rn

# Show compiler version
compiler-info:
	@$(CC) --version
	@echo ""
	@$(CC) -dumpmachine

# Generate compile_commands.json for IDE/LSP support
compile_commands.json: $(SRCS)
	@echo "Generating compile_commands.json..."
	@echo '[' > $@
	@first=1; \
	for f in $(SRCS); do \
	    if [ $$first -eq 0 ]; then echo ',' >> $@; fi; \
	    echo "  {" >> $@; \
	    echo "    \"directory\": \"$(CURDIR)\"," >> $@; \
	    echo "    \"command\": \"$(CC) $(CFLAGS) -c $$f\"," >> $@; \
	    echo "    \"file\": \"$(CURDIR)/$$f\"" >> $@; \
	    echo -n "  }" >> $@; \
	    first=0; \
	done; \
	echo '' >> $@
	@echo ']' >> $@
	@echo "Generated: $@"

.PHONY: rebuild loc compiler-info compile_commands.json \
        termux-install bench-quick valgrind gdb gprof \
        dist-src strip-binary

# =============================================================================
# END OF Makefile
# =============================================================================

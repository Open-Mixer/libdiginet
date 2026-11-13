# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# libdiginet: the DigiNet protocol (frame grammar, codecs, personalities) as libdiginet.a,
# and the wire under it (packet socket, session) as libdiginet-transport.a. See BUILDING.md.
#
# `make shared` and `make install-shared` are what the packages build: the same objects as
# shared libraries, and diginet-probe linked against them.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
LDFLAGS ?=
# -fPIC always: the same objects go into the archives and the shared libraries.
WARN    := -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -fPIC
INC     := -Iinclude
PREFIX  ?= /usr/local
LIBDIR  ?= $(PREFIX)/lib
INCDIR  ?= $(PREFIX)/include
BINDIR  ?= $(PREFIX)/bin
PCDIR   ?= $(LIBDIR)/pkgconfig
DATADIR ?= $(PREFIX)/share
MANDIR  ?= $(DATADIR)/man
DESTDIR ?=

# The version is the VERSION file; the sonames' majors are in diginet.h. The header's version
# string and the packaging copies are held to them by tests/conformance-packaging.sh.
VERSION := $(shell cat VERSION)
ABI     := $(shell sed -n 's/^\#define DIGINET_ABI  *\([0-9]*\)$$/\1/p' include/diginet/diginet.h)
TABI    := $(shell sed -n 's/^\#define DIGINET_TRANSPORT_ABI  *\([0-9]*\)$$/\1/p' include/diginet/diginet.h)

OBJS := src/diginet_frame.o src/diginet_msg.o src/diginet_codec.o src/diginet_decode.o src/diginet_census.o src/diginet_census_c24.o

TOBJS := transport/src/diginet_io.o transport/src/diginet_session.o transport/src/diginet_mux.o

# The desk emulator (testsupport/desk_emu.c): installed test support, so a project testing
# against a Control|24 or ProControl links it instead of keeping its own copy (#58).
EOBJS := testsupport/desk_emu.o

TESTS := tests/test_frame tests/test_codec tests/test_transport tests/test_mux tests/test_fdio tests/test_packet

GOLDEN := tests/golden/frames.txt
RUN_TEST := tests/run-test.sh

PROBE := tools/diginet-probe
HELPER := tools/diginet-packet-helper
CENSUS := tools/diginet-census

all: libdiginet.a libdiginet-transport.a libdiginet-emu.a $(PROBE) $(HELPER)

# -MMD -MP: a header edit rebuilds every object that includes it.
src/%.o: src/%.c
	$(CC) $(CFLAGS) $(WARN) -MMD -MP $(INC) -c $< -o $@

transport/src/%.o: transport/src/%.c
	$(CC) $(CFLAGS) $(WARN) -MMD -MP $(INC) -c $< -o $@

testsupport/%.o: testsupport/%.c
	$(CC) $(CFLAGS) $(WARN) -MMD -MP $(INC) -c $< -o $@

-include $(OBJS:.o=.d) $(TOBJS:.o=.d) $(EOBJS:.o=.d)

libdiginet.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

libdiginet-transport.a: $(TOBJS)
	$(AR) rcs $@ $(TOBJS)

libdiginet-emu.a: $(EOBJS)
	$(AR) rcs $@ $(EOBJS)

tests/test_frame: tests/test_frame.c tests/golden.h libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet.a -o $@

tests/test_codec: tests/test_codec.c tests/golden.h libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet.a -o $@

tests/test_transport tests/test_mux: tests/%: tests/%.c tests/golden.h libdiginet-emu.a libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-emu.a libdiginet-transport.a libdiginet.a -o $@

tests/test_fdio tests/test_packet: tests/%: tests/%.c tests/golden.h libdiginet-emu.a libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-emu.a libdiginet-transport.a libdiginet.a -o $@

$(PROBE): tools/diginet-probe.c libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-transport.a libdiginet.a $(LDFLAGS) -o $@

$(CENSUS): tools/diginet-census.c libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-transport.a libdiginet.a $(LDFLAGS) -o $@

# The helper links the archives even in the packages: a program that holds a capability loads no
# shared library it could be handed in place of ours.
$(HELPER): tools/diginet-packet-helper.c libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-transport.a libdiginet.a $(LDFLAGS) -o $@

# ---- shared libraries (the packages) -------------------------------------------------------
# --no-undefined: a symbol nothing defines fails here, not at a consumer's link.
SO  := libdiginet.so.$(VERSION)
TSO := libdiginet-transport.so.$(VERSION)

$(SO): $(OBJS)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,libdiginet.so.$(ABI) -Wl,--no-undefined -o $@ $(OBJS)
	ln -sf $@ libdiginet.so.$(ABI)
	ln -sf libdiginet.so.$(ABI) libdiginet.so

$(TSO): $(TOBJS) $(SO)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,libdiginet-transport.so.$(TABI) -Wl,--no-undefined \
	    -o $@ $(TOBJS) -L. -ldiginet
	ln -sf $@ libdiginet-transport.so.$(TABI)
	ln -sf libdiginet-transport.so.$(TABI) libdiginet-transport.so

build/diginet-probe build/diginet-census: build/%: tools/%.c $(TSO) $(SO)
	@mkdir -p build
	$(CC) $(CFLAGS) $(WARN) $(INC) $< $(LDFLAGS) -L. -ldiginet-transport -ldiginet -o $@

shared: $(SO) $(TSO) build/diginet-probe build/diginet-census $(HELPER)

tests/test_anyif: tests/test_anyif.c tests/golden.h libdiginet-emu.a libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-emu.a libdiginet-transport.a libdiginet.a -o $@

tests/test_probe: tests/test_probe.c tests/golden.h libdiginet-emu.a libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-emu.a libdiginet-transport.a libdiginet.a -o $@

# The census against the emulator, and a desk's recorded bodies read back when the file is there.
tests/test_census: tests/test_census.c tests/golden.h libdiginet-emu.a libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-emu.a libdiginet-transport.a libdiginet.a -o $@

# The child harness the module tests of libsurface and the console run on, proved on the probe.
tests/test_emu_child: tests/test_emu_child.c include/diginet/testsupport/emu_child.h libdiginet-emu.a libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-emu.a libdiginet-transport.a libdiginet.a -o $@

test: $(TESTS) tests/test_probe tests/test_anyif tests/test_emu_child tests/test_census $(PROBE) $(HELPER) $(CENSUS)
	$(RUN_TEST) tests/test_frame $(GOLDEN)
	$(RUN_TEST) tests/test_codec $(GOLDEN)
	$(RUN_TEST) tests/test_transport
	$(RUN_TEST) tests/test_mux
	$(RUN_TEST) tests/test_fdio $(HELPER)
	$(RUN_TEST) tests/test_packet
	$(RUN_TEST) tests/test_anyif $(HELPER) $(PROBE)
	$(RUN_TEST) tests/test_probe $(PROBE)
	$(RUN_TEST) tests/test_emu_child $(PROBE)
	$(RUN_TEST) tests/test_census $(CENSUS) tests/golden/census-c24.txt
	$(RUN_TEST) tests/test_install.sh
	$(RUN_TEST) tests/conformance-packaging.sh
	$(RUN_TEST) tests/test_workflows.sh

# No tracked file points into a private repository: Open-Mixer/.github's private-refs check, from a
# checkout of it (OPENMIXER_DOTGITHUB, else ../freemixer-dotgithub). CI runs it, with the commit
# message check, through the public-sources-check workflow; `make test` does not, so the package
# builds need no such checkout.
OPENMIXER_DOTGITHUB ?= ../freemixer-dotgithub
public-sources:
	$(OPENMIXER_DOTGITHUB)/.github/actions/private-refs-check/check.sh .

# The Kaitai grammar compiles, and the parser it generates reads the golden frames with
# the values the C suite asserts, and the frames captured from a Control|24 with the values
# the wire holds (tests/ksy/wire_frames.txt). Needs kaitai-struct-compiler 0.11 and the Python
# runtime.
KSY_OUT := build/ksy
ksy-check:
	@mkdir -p $(KSY_OUT)
	kaitai-struct-compiler -t python --outdir $(KSY_OUT) protocol/diginet.ksy
	python3 tests/ksy/check_golden.py $(KSY_OUT) $(GOLDEN)
	python3 tests/ksy/check_wire.py $(KSY_OUT) tests/ksy/wire_frames.txt

# ---- fuzzing (fuzz/README.md) ----------------------------------------------------------------
# One libFuzzer harness per reader of desk bytes in fuzz/, each linked against a library of its
# own: the same sources compiled with clang, AddressSanitizer, UndefinedBehaviorSanitizer and
# libFuzzer's coverage hooks into build/fuzz/obj, so the ordinary build above is never touched.
# None of these targets is part of `make test`.
#   make fuzz                   build every harness
#   make fuzz-run FUZZ_TIME=60  fuzz each for the budget; red on any crash, the input left in
#                               fuzz/findings/
#   make fuzz-sabotage          each patch of fuzz/sabotage/ must make its harness abort on a
#                               seed, in the property its header names
#   make fuzz-records           each check's mutant: and input: record, alone, must make that
#                               check abort on that seed; red on a check with no record and no
#                               not-a-property line
#   make fuzz-coverage          line coverage of each reader over its seed corpus, red below
#                               fuzz/coverage-floor.txt or on a property check no seed reaches
#   make fuzz-static            each harness linked fully static with a plain driver, over its
#                               corpus
#   make fuzz-corpus            write fuzz/corpus/ again from the golden frames and the builders
#   make fuzz-corpus-check      red when fuzz/corpus/ is not what fuzz-corpus writes
FUZZ_CC        ?= clang
FUZZ_TIME      ?= 60
FUZZ_BUILD     := build/fuzz
FUZZ_HARNESSES := frame decode codec transport mux
FUZZ_SAN       := -fsanitize=address,undefined -fno-sanitize-recover=all
FUZZ_CFLAGS    := -O1 -g -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -fno-omit-frame-pointer
# What the harnesses drive: the protocol library, the session and the mux (not the socket code).
FUZZ_SRCS      := $(OBJS:.o=.c) transport/src/diginet_session.c transport/src/diginet_mux.c
FUZZ_LIB       := $(FUZZ_BUILD)/libdiginet-fuzz.a
FUZZ_BINS      := $(FUZZ_HARNESSES:%=$(FUZZ_BUILD)/fuzz_%)

$(FUZZ_BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_SAN) -fsanitize=fuzzer-no-link -MMD -MP $(INC) -c $< -o $@

$(FUZZ_LIB): $(FUZZ_SRCS:%.c=$(FUZZ_BUILD)/obj/%.o)
	$(AR) rcs $@ $^

$(FUZZ_BUILD)/fuzz_%: fuzz/fuzz_%.c fuzz/fuzz.h fuzz/spec.h $(FUZZ_LIB)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $(FUZZ_SAN) -fsanitize=fuzzer -MMD -MP -MF $@.d $(INC) $< $(FUZZ_LIB) -o $@

fuzz: $(FUZZ_BINS)

fuzz-run: fuzz
	FUZZ_BUILD=$(FUZZ_BUILD) FUZZ_TIME=$(FUZZ_TIME) fuzz/run.sh $(FUZZ_HARNESSES)

fuzz-sabotage:
	FUZZ_BUILD=$(FUZZ_BUILD) MAKE="$(MAKE)" fuzz/sabotage.sh

# Each record built plain and native with fuzz/standalone.c for its driver, no sanitizer, as the
# OSS Verify coverage build is.
fuzz-records:
	FUZZ_BUILD=$(FUZZ_BUILD) FUZZ_CC=$(FUZZ_CC) fuzz/records.sh $(FUZZ_HARNESSES)

# The same harnesses driven by fuzz/standalone.c instead of libFuzzer and linked fully static,
# each run over its corpus: the build a verifier that brings its own driver takes. Needs the
# static libc (glibc-static on Fedora).
FUZZ_STATIC_BUILD := $(FUZZ_BUILD)/static
FUZZ_STATIC_FLAGS := -O2 -g -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE

$(FUZZ_STATIC_BUILD)/fuzz_%: fuzz/fuzz_%.c fuzz/fuzz.h fuzz/spec.h fuzz/standalone.c $(FUZZ_SRCS)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(FUZZ_STATIC_FLAGS) -static $(INC) -Ifuzz $< fuzz/standalone.c $(FUZZ_SRCS) -o $@

fuzz-static: $(FUZZ_HARNESSES:%=$(FUZZ_STATIC_BUILD)/fuzz_%)
	@for h in $(FUZZ_HARNESSES); do \
	  if readelf -lW $(FUZZ_STATIC_BUILD)/fuzz_$$h | grep -qE 'INTERP|DYNAMIC'; then \
	    echo "fuzz-static: fuzz_$$h is not static"; exit 1; fi; \
	  out=$$($(FUZZ_STATIC_BUILD)/fuzz_$$h fuzz/corpus/$$h/* 2>&1) || \
	    { echo "$$out"; echo "fuzz-static: fuzz_$$h failed on its own corpus"; exit 1; }; \
	  echo "fuzz_$$h, static: $$out"; done

# The coverage witness: the same harnesses without sanitizers, instrumented for llvm-cov, each
# run once over its seed corpus (-runs=0 executes the corpus and nothing else); the llvm-cov
# and llvm-profdata of FUZZ_CC's own LLVM.
FUZZ_COV_BUILD := $(FUZZ_BUILD)/cov
FUZZ_COV_FLAGS := -O0 -g -std=c11 -D_DEFAULT_SOURCE -fprofile-instr-generate -fcoverage-mapping
FUZZ_COV_LIB   := $(FUZZ_COV_BUILD)/libdiginet-cov.a
LLVM_COV       ?= llvm-cov
LLVM_PROFDATA  ?= llvm-profdata

$(FUZZ_COV_BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(FUZZ_CC) $(FUZZ_COV_FLAGS) -MMD -MP $(INC) -c $< -o $@

$(FUZZ_COV_LIB): $(FUZZ_SRCS:%.c=$(FUZZ_COV_BUILD)/obj/%.o)
	$(AR) rcs $@ $^

$(FUZZ_COV_BUILD)/fuzz_%: fuzz/fuzz_%.c fuzz/fuzz.h fuzz/spec.h $(FUZZ_COV_LIB)
	$(FUZZ_CC) $(FUZZ_COV_FLAGS) -fsanitize=fuzzer $(INC) $< $(FUZZ_COV_LIB) -o $@

fuzz-coverage: $(FUZZ_HARNESSES:%=$(FUZZ_COV_BUILD)/fuzz_%)
	@set -e; for h in $(FUZZ_HARNESSES); do \
	  rm -f $(FUZZ_COV_BUILD)/$$h.profraw; \
	  LLVM_PROFILE_FILE=$(FUZZ_COV_BUILD)/$$h.profraw $(FUZZ_COV_BUILD)/fuzz_$$h -runs=0 \
	      fuzz/corpus/$$h/ >$(FUZZ_COV_BUILD)/$$h.log 2>&1 || \
	    { cat $(FUZZ_COV_BUILD)/$$h.log; echo "fuzz-coverage: fuzz_$$h failed on its own corpus"; exit 1; }; \
	  $(LLVM_PROFDATA) merge -sparse $(FUZZ_COV_BUILD)/$$h.profraw -o $(FUZZ_COV_BUILD)/$$h.profdata; \
	done
	@LLVM_COV=$(LLVM_COV) fuzz/coverage.sh $(FUZZ_COV_BUILD) $(FUZZ_HARNESSES)

# The seed corpus is written from tests/golden/frames.txt and the library's own builders, never
# from a network or a capture, and committed.
FUZZ_GEN := build/fuzz-gen-corpus
$(FUZZ_GEN): fuzz/gen-corpus.c tests/golden.h libdiginet.a
	@mkdir -p build
	$(CC) $(CFLAGS) $(WARN) $(INC) -Itests $< libdiginet.a -o $@

fuzz-corpus: $(FUZZ_GEN)
	rm -rf fuzz/corpus
	$(FUZZ_GEN) $(GOLDEN) fuzz/corpus

fuzz-corpus-check: $(FUZZ_GEN)
	@rm -rf build/fuzz-corpus-check
	@$(FUZZ_GEN) $(GOLDEN) build/fuzz-corpus-check
	@diff -r build/fuzz-corpus-check fuzz/corpus && echo "fuzz/corpus is what fuzz-corpus writes"

-include $(FUZZ_SRCS:%.c=$(FUZZ_BUILD)/obj/%.d) $(FUZZ_BINS:=.d)

# The pkg-config files are written at install time, from the install's own PREFIX and LIBDIR:
# a file kept from an earlier build would name that build's directories.
PCSED = sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@LIBDIR@|$(LIBDIR)|' -e 's|@INCDIR@|$(INCDIR)|' \
	    -e 's|@VERSION@|$(VERSION)|'

# What both installs carry: headers, pkg-config files, the grammar, the manual page.
install-common:
	install -d $(DESTDIR)$(INCDIR)/diginet/transport $(DESTDIR)$(INCDIR)/diginet/testsupport $(DESTDIR)$(PCDIR) \
	    $(DESTDIR)$(BINDIR) $(DESTDIR)$(DATADIR)/diginet $(DESTDIR)$(MANDIR)/man1
	install -m 644 include/diginet/*.h $(DESTDIR)$(INCDIR)/diginet/
	install -m 644 include/diginet/transport/*.h $(DESTDIR)$(INCDIR)/diginet/transport/
	install -m 644 include/diginet/testsupport/*.h $(DESTDIR)$(INCDIR)/diginet/testsupport/
	$(PCSED) packaging/libdiginet.pc.in > $(DESTDIR)$(PCDIR)/libdiginet.pc
	$(PCSED) packaging/libdiginet-transport.pc.in > $(DESTDIR)$(PCDIR)/libdiginet-transport.pc
	$(PCSED) packaging/libdiginet-emu.pc.in > $(DESTDIR)$(PCDIR)/libdiginet-emu.pc
	install -m 644 protocol/diginet.ksy $(DESTDIR)$(DATADIR)/diginet/
	install -m 644 docs/diginet-probe.1 docs/diginet-packet-helper.1 docs/diginet-census.1 $(DESTDIR)$(MANDIR)/man1/

# libdiginet-emu is installed test support, not a runtime library: a static archive in either
# install, which the packages carry in their development package only, beside its headers and
# its pkg-config file.
install: libdiginet.a libdiginet-transport.a libdiginet-emu.a $(PROBE) $(HELPER) $(CENSUS) install-common
	install -d $(DESTDIR)$(LIBDIR)
	install -m 644 libdiginet.a libdiginet-transport.a libdiginet-emu.a $(DESTDIR)$(LIBDIR)/
	install -m 755 $(PROBE) $(HELPER) $(CENSUS) $(DESTDIR)$(BINDIR)/

# The packages: shared libraries with their soname links, the probe linked against them.
install-shared: shared libdiginet-emu.a $(HELPER) install-common
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(SO) $(TSO) $(DESTDIR)$(LIBDIR)/
	install -m 644 libdiginet-emu.a $(DESTDIR)$(LIBDIR)/
	ln -sf $(SO) $(DESTDIR)$(LIBDIR)/libdiginet.so.$(ABI)
	ln -sf libdiginet.so.$(ABI) $(DESTDIR)$(LIBDIR)/libdiginet.so
	ln -sf $(TSO) $(DESTDIR)$(LIBDIR)/libdiginet-transport.so.$(TABI)
	ln -sf libdiginet-transport.so.$(TABI) $(DESTDIR)$(LIBDIR)/libdiginet-transport.so
	install -m 755 build/diginet-probe build/diginet-census $(HELPER) $(DESTDIR)$(BINDIR)/

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TOBJS) $(TOBJS:.o=.d) $(EOBJS) $(EOBJS:.o=.d) \
	    libdiginet.a libdiginet-transport.a libdiginet-emu.a *.pc $(TESTS) tests/test_probe tests/test_anyif \
	    tests/test_emu_child tests/test_census $(PROBE) $(HELPER) $(CENSUS) build/diginet-census
	rm -f libdiginet.so* libdiginet-transport.so*
	rm -rf build

.PHONY: all test ksy-check public-sources shared install install-common install-shared clean \
	fuzz fuzz-run fuzz-sabotage fuzz-records fuzz-coverage fuzz-static fuzz-corpus fuzz-corpus-check

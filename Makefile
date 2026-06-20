# Build shachain2pc. Run inside the flake dev shell:
#   nix develop          # builds the pinned, patched emp stack via nix into
#                        # /nix/store and exports EMP_PREFIX (+ a .deps/emp symlink)
#   nix develop -c make
#
# emp (emp-tool lib + emp-ot/emp-ag2pc headers) is built reproducibly by the nix
# flake (packages.emp) into /nix/store; EMP_PREFIX points there. OpenSSL comes
# from the nix shell via pkg-config. EMP_PREFIX falls back to .deps/emp when unset
# (e.g. a legacy bootstrap checkout).

CXX ?= g++
EMP_PREFIX ?= .deps/emp

# Allow -march=native through nix's cc-wrapper (strips native arch by default).
export NIX_ENFORCE_NO_NATIVE := 0

# Tune for the host CPU (AVX2/FMA/BMI2 over the old SSE4.2 baseline). The
# header-only emp-ag2pc engine -- the dominant per-AND garbling cost -- is
# compiled into the party here, so these flags hit the hot path directly.
# LTO inlines across our TUs (compile+link is one step). Release-grade -O3.
ARCH := -march=native
CXXFLAGS := -std=c++20 -O3 -flto -pthread $(ARCH)

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)

EMP_CFLAGS := -isystem $(EMP_PREFIX)/include -Wno-stringop-overread
EMP_LIBS := -L$(EMP_PREFIX)/lib -L$(EMP_PREFIX)/lib64 \
            -Wl,-rpath,$(EMP_PREFIX)/lib -Wl,-rpath,$(EMP_PREFIX)/lib64 \
            -lemp-ot -lemp-tool

BUILD := .build

REF_SRC := reference/shachain_ref.cpp
PROTO_SRC := protocol/bristol.cpp protocol/circuit_gen.cpp
RUN_DEPS := run/derive.h protocol/bristol.h protocol/circuit_gen.h \
            protocol/wire_layout.h util/hex.h

# Targets that need only OpenSSL (no emp / no MPC).
PLAIN_BINS := $(BUILD)/ref_kat $(BUILD)/ref_cli $(BUILD)/verify_circuit \
              $(BUILD)/probe_convention $(BUILD)/tamper_circuit
# Targets that link the emp MPC engine. Only the party binary is ported to the
# rewritten emp-ag2pc. The old Rust-interop probes (emp_wire_probe, otco/iknp/
# fpre_*/c2pc_* probes) and measure_io/compat_probe target the OLD emp API
# (emp-ag2pc/helper.h, fpre.h, 2pc.h, the old emp::C2PC) which the new emp install
# no longer provides; their tools/*.cpp are kept for the eventual Rust re-port but
# are NOT built. See docs/new-emp-ag2pc-notes.md.
EMP_BINS := $(BUILD)/party $(BUILD)/ag2pc_session_probe \
            $(BUILD)/ag2pc_transport_probe $(BUILD)/softspoken_probe \
            $(BUILD)/softspoken_helper_probe $(BUILD)/csw_helper_probe \
            $(BUILD)/mitccrh_helper_probe \
            $(BUILD)/csw_probe $(BUILD)/ag2pc_triple_pool_probe \
            $(BUILD)/ag2pc_protocol_probe $(BUILD)/ag2pc_compute_probe

.PHONY: all plain mpc clean test test-cache-tamper test-ag2pc-probe \
        test-softspoken-probe test-softspoken-helper-probe \
        test-csw-helper-probe test-mitccrh-helper-probe \
        test-ag2pc-triple-pool-probe test-ag2pc-protocol-probe \
        test-ag2pc-compute-probe demo cheat
all: plain mpc
plain: $(PLAIN_BINS)
mpc: $(EMP_BINS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/ref_kat: reference/ref_kat.cpp $(REF_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/ref_cli: reference/ref_cli.cpp $(REF_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/verify_circuit: tools/verify_circuit.cpp $(PROTO_SRC) $(REF_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/probe_convention: tools/probe_convention.cpp $(PROTO_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/tamper_circuit: tools/tamper_circuit.cpp $(PROTO_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/party: demo/party.cpp $(PROTO_SRC) $(RUN_DEPS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) demo/party.cpp $(PROTO_SRC) \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/ag2pc_session_probe: tools/ag2pc_session_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/ag2pc_transport_probe: tools/ag2pc_transport_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/softspoken_probe: tools/softspoken_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/softspoken_helper_probe: tools/softspoken_helper_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/csw_helper_probe: tools/csw_helper_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/mitccrh_helper_probe: tools/mitccrh_helper_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/csw_probe: tools/csw_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/ag2pc_triple_pool_probe: tools/ag2pc_triple_pool_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/ag2pc_protocol_probe: tools/ag2pc_protocol_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/ag2pc_compute_probe: tools/ag2pc_compute_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

# `test` builds the new-emp party (compile gate) and runs the plain (no-MPC) KATs:
# the BOLT-03 reference vectors and the plaintext circuit verifier.
test: $(BUILD)/ref_kat $(BUILD)/ref_cli $(BUILD)/verify_circuit $(BUILD)/party
	./$(BUILD)/ref_kat
	./$(BUILD)/verify_circuit

test-ag2pc-probe: $(BUILD)/ag2pc_session_probe
	set -e; \
	port=$$(python3 -c 'import random; print(random.randrange(20000, 60000))'); \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_session_probe 1 $$port \
	  >$(BUILD)/ag2pc_probe_alice.jsonl \
	  2>$(BUILD)/ag2pc_probe_alice.err & \
	alice=$$!; \
	sleep 0.2; \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_session_probe 2 $$port \
	  >$(BUILD)/ag2pc_probe_bob.jsonl \
	  2>$(BUILD)/ag2pc_probe_bob.err; \
	bob=$$?; \
	wait $$alice; \
	alice_status=$$?; \
	test $$alice_status -eq 0; \
	test $$bob -eq 0; \
	test ! -s $(BUILD)/ag2pc_probe_alice.err; \
	test ! -s $(BUILD)/ag2pc_probe_bob.err; \
	test $$(wc -l <$(BUILD)/ag2pc_probe_alice.jsonl) -eq 9; \
	test $$(wc -l <$(BUILD)/ag2pc_probe_bob.jsonl) -eq 9; \
	python3 tools/check_ag2pc_probe.py \
	  $(BUILD)/ag2pc_probe_alice.jsonl $(BUILD)/ag2pc_probe_bob.jsonl

test-softspoken-probe: $(BUILD)/softspoken_probe
	set -e; \
	port=$$(python3 -c 'import random; print(random.randrange(20000, 60000))'); \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/softspoken_probe 1 $$port \
	  >$(BUILD)/softspoken_probe_alice.json \
	  2>$(BUILD)/softspoken_probe_alice.err & \
	alice=$$!; \
	sleep 0.2; \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/softspoken_probe 2 $$port \
	  >$(BUILD)/softspoken_probe_bob.json \
	  2>$(BUILD)/softspoken_probe_bob.err; \
	bob=$$?; \
	wait $$alice; \
	alice_status=$$?; \
	test $$alice_status -eq 0; \
	test $$bob -eq 0; \
	test ! -s $(BUILD)/softspoken_probe_alice.err; \
	test ! -s $(BUILD)/softspoken_probe_bob.err; \
	python3 -c 'import json,sys; \
	  rs=[json.load(open(p)) for p in sys.argv[1:]]; \
	  assert all(r["verified"] for r in rs); \
	  assert rs[0]["digest"] == rs[1]["digest"]; \
	  assert rs[0]["delta"] == rs[1]["delta"]' \
	  $(BUILD)/softspoken_probe_alice.json $(BUILD)/softspoken_probe_bob.json

test-softspoken-helper-probe: $(BUILD)/softspoken_helper_probe
	./$(BUILD)/softspoken_helper_probe >$(BUILD)/softspoken_helper_probe.json
	diff -u compat/ag2pc/softspoken-helper-v1.json \
	  $(BUILD)/softspoken_helper_probe.json

test-csw-helper-probe: $(BUILD)/csw_helper_probe
	./$(BUILD)/csw_helper_probe >$(BUILD)/csw_helper_probe.json
	diff -u compat/ag2pc/csw-helper-v1.json \
	  $(BUILD)/csw_helper_probe.json

test-mitccrh-helper-probe: $(BUILD)/mitccrh_helper_probe
	./$(BUILD)/mitccrh_helper_probe >$(BUILD)/mitccrh_helper_probe.json
	diff -u compat/ag2pc/mitccrh-helper-v1.json \
	  $(BUILD)/mitccrh_helper_probe.json

test-ag2pc-triple-pool-probe: $(BUILD)/ag2pc_triple_pool_probe
	set -e; \
	port=$$(python3 -c 'import random; print(random.randrange(20000, 60000))'); \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_triple_pool_probe 1 $$port \
	  >$(BUILD)/ag2pc_triple_pool_probe_alice.json \
	  2>$(BUILD)/ag2pc_triple_pool_probe_alice.err & \
	alice=$$!; \
	sleep 0.2; \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_triple_pool_probe 2 $$port \
	  >$(BUILD)/ag2pc_triple_pool_probe_bob.json \
	  2>$(BUILD)/ag2pc_triple_pool_probe_bob.err; \
	bob=$$?; \
	wait $$alice; \
	alice_status=$$?; \
	test $$alice_status -eq 0; \
	test $$bob -eq 0; \
	test ! -s $(BUILD)/ag2pc_triple_pool_probe_alice.err; \
	test ! -s $(BUILD)/ag2pc_triple_pool_probe_bob.err; \
	python3 -c 'import json,sys; \
	  rs=[json.load(open(p)) for p in sys.argv[1:]]; \
	  assert all(r["verified"] for r in rs)' \
	  $(BUILD)/ag2pc_triple_pool_probe_alice.json \
	  $(BUILD)/ag2pc_triple_pool_probe_bob.json

test-ag2pc-protocol-probe: $(BUILD)/ag2pc_protocol_probe
	set -e; \
	port=$$(python3 -c 'import random; print(random.randrange(20000, 60000))'); \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_protocol_probe 1 $$port \
	  >$(BUILD)/ag2pc_protocol_probe_alice.json \
	  2>$(BUILD)/ag2pc_protocol_probe_alice.err & \
	alice=$$!; \
	sleep 0.2; \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_protocol_probe 2 $$port \
	  >$(BUILD)/ag2pc_protocol_probe_bob.json \
	  2>$(BUILD)/ag2pc_protocol_probe_bob.err; \
	bob=$$?; \
	wait $$alice; \
	alice_status=$$?; \
	test $$alice_status -eq 0; \
	test $$bob -eq 0; \
	test ! -s $(BUILD)/ag2pc_protocol_probe_alice.err; \
	test ! -s $(BUILD)/ag2pc_protocol_probe_bob.err; \
	python3 -c 'import json,sys; \
	  rs=[json.load(open(p)) for p in sys.argv[1:]]; \
	  assert all(r["verified"] for r in rs); \
	  assert all(r["process_input_calls"] == 1 for r in rs)' \
	  $(BUILD)/ag2pc_protocol_probe_alice.json \
	  $(BUILD)/ag2pc_protocol_probe_bob.json

test-ag2pc-compute-probe: $(BUILD)/ag2pc_compute_probe
	set -e; \
	port=$$(python3 -c 'import random; print(random.randrange(20000, 60000))'); \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_compute_probe 1 $$port \
	  >$(BUILD)/ag2pc_compute_probe_alice.json \
	  2>$(BUILD)/ag2pc_compute_probe_alice.err & \
	alice=$$!; \
	sleep 0.2; \
	SHACHAIN2PC_TIMEOUT_SECS=60 ./$(BUILD)/ag2pc_compute_probe 2 $$port \
	  >$(BUILD)/ag2pc_compute_probe_bob.json \
	  2>$(BUILD)/ag2pc_compute_probe_bob.err; \
	bob=$$?; \
	wait $$alice; \
	alice_status=$$?; \
	test $$alice_status -eq 0; \
	test $$bob -eq 0; \
	test ! -s $(BUILD)/ag2pc_compute_probe_alice.err; \
	test ! -s $(BUILD)/ag2pc_compute_probe_bob.err; \
	python3 -c 'import json,sys; \
	  rs=[json.load(open(p)) for p in sys.argv[1:]]; \
	  assert all(r["verified"] for r in rs)' \
	  $(BUILD)/ag2pc_compute_probe_alice.json \
	  $(BUILD)/ag2pc_compute_probe_bob.json

test-cache-tamper: $(BUILD)/party $(BUILD)/ref_cli
	./demo/cache_tamper_test.sh

demo: all
	./demo/run_demo.sh

cheat: all
	./demo/run_cheat.sh

clean:
	rm -rf $(BUILD)

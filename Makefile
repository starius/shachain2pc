# Build shachain2pc. Run inside the flake dev shell:
#   nix develop -c ./tools/bootstrap-emp.sh   # once: fetch + build emp
#   nix develop -c make
#
# emp (emp-tool lib + emp-ot/emp-ag2pc headers) lives in .deps/emp after
# bootstrap; OpenSSL comes from the nix shell via pkg-config.

CXX ?= g++
EMP_PREFIX := .deps/emp

SIMD := -mssse3 -msse4.1 -maes -mpclmul
CXXFLAGS := -std=c++17 -O2 -pthread $(SIMD)

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)

EMP_CFLAGS := -I$(EMP_PREFIX)/include
EMP_LIBS := -L$(EMP_PREFIX)/lib -Wl,-rpath,$(EMP_PREFIX)/lib -lemp-tool

BUILD := .build

REF_SRC := reference/shachain_ref.cpp
PROTO_SRC := protocol/bristol.cpp protocol/circuit_gen.cpp

# Targets that need only OpenSSL (no emp / no MPC).
PLAIN_BINS := $(BUILD)/ref_kat $(BUILD)/ref_cli $(BUILD)/verify_circuit \
              $(BUILD)/probe_convention $(BUILD)/gen_circuit \
              $(BUILD)/tamper_circuit
# Targets that link the emp MPC engine.
EMP_BINS := $(BUILD)/party $(BUILD)/measure_io

.PHONY: all plain mpc clean test demo cheat
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

$(BUILD)/gen_circuit: demo/gen_circuit.cpp $(PROTO_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/tamper_circuit: tools/tamper_circuit.cpp $(PROTO_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(OPENSSL_CFLAGS) $^ $(OPENSSL_LIBS) -o $@

$(BUILD)/party: demo/party.cpp protocol/bristol.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $^ \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/measure_io: tools/measure_io.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) $< \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

test: $(BUILD)/ref_kat $(BUILD)/verify_circuit
	./$(BUILD)/ref_kat
	./$(BUILD)/verify_circuit

demo: all
	./demo/run_demo.sh

cheat: all
	./demo/run_cheat.sh

clean:
	rm -rf $(BUILD)

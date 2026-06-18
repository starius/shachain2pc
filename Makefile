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

EMP_CFLAGS := -isystem $(EMP_PREFIX)/include -Wno-stringop-overread
EMP_LIBS := -L$(EMP_PREFIX)/lib -Wl,-rpath,$(EMP_PREFIX)/lib -lemp-tool

BUILD := .build

REF_SRC := reference/shachain_ref.cpp
PROTO_SRC := protocol/bristol.cpp protocol/circuit_gen.cpp
RUN_DEPS := run/derive.h protocol/bristol.h protocol/circuit_gen.h \
            protocol/wire_layout.h util/hex.h

# Targets that need only OpenSSL (no emp / no MPC).
PLAIN_BINS := $(BUILD)/ref_kat $(BUILD)/ref_cli $(BUILD)/verify_circuit \
              $(BUILD)/probe_convention $(BUILD)/tamper_circuit
# Targets that link the emp MPC engine.
EMP_BINS := $(BUILD)/party $(BUILD)/measure_io $(BUILD)/compat_probe \
            $(BUILD)/emp_wire_probe $(BUILD)/otco_probe

.PHONY: all plain mpc clean test demo cheat compat-probe
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

$(BUILD)/measure_io: tools/measure_io.cpp $(PROTO_SRC) $(RUN_DEPS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) tools/measure_io.cpp $(PROTO_SRC) \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/compat_probe: tools/compat_probe.cpp $(PROTO_SRC) $(REF_SRC) $(RUN_DEPS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) tools/compat_probe.cpp \
	    $(PROTO_SRC) $(REF_SRC) $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/emp_wire_probe: tools/emp_wire_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) tools/emp_wire_probe.cpp \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

$(BUILD)/otco_probe: tools/otco_probe.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(EMP_CFLAGS) $(OPENSSL_CFLAGS) tools/otco_probe.cpp \
	    $(EMP_LIBS) $(OPENSSL_LIBS) -o $@

test: $(BUILD)/ref_kat $(BUILD)/verify_circuit $(BUILD)/emp_wire_probe \
      $(BUILD)/otco_probe
	./$(BUILD)/ref_kat
	./$(BUILD)/verify_circuit

demo: all
	./demo/run_demo.sh

cheat: all
	./demo/run_cheat.sh

compat-probe: $(BUILD)/compat_probe
	@./$(BUILD)/compat_probe

clean:
	rm -rf $(BUILD)

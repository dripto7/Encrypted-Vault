# Test suites.
#
# Three tiers, because they need different things from the environment:
#   unit        - no kernel module, no privileges. Always runnable.
#   integration - needs kvault.ko loaded and the device openable.
#   system      - needs root, the test users, and reloads the module itself.
#
# Each suite is its own binary rather than one runner with flags: a test that
# wedges the kernel takes down one binary, and the others still report.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic \
            -I../include -I../src -I../src/client -I../src/sim -I..
LDLIBS   ?= -lcrypto -lpthread

BUILD    := ../build/tests
CLIENT   := $(wildcard ../src/client/*.cpp)
# The simulator's parser and principal classes, minus its main().
SIMLIB   := ../src/sim/ScenarioLoader.cpp ../src/sim/SimUser.cpp

UNIT_SRC := $(wildcard unit/*.cpp)
INT_SRC  := $(wildcard integration/*.cpp)
SYS_SRC  := $(filter-out system/bench_%.cpp,$(wildcard system/*.cpp))
BENCH_SRC := $(wildcard system/bench_*.cpp)

UNIT_BIN := $(UNIT_SRC:%.cpp=$(BUILD)/%)
INT_BIN  := $(INT_SRC:%.cpp=$(BUILD)/%)
SYS_BIN  := $(SYS_SRC:%.cpp=$(BUILD)/%)
BENCH_BIN := $(BENCH_SRC:%.cpp=$(BUILD)/%)

.PHONY: all run unit integration system bench clean

all: $(UNIT_BIN) $(INT_BIN) $(SYS_BIN) $(BENCH_BIN)

$(BUILD)/%: %.cpp $(CLIENT) $(SIMLIB)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $< $(CLIENT) $(SIMLIB) -o $@ $(LDLIBS)

run: unit integration system

unit: $(UNIT_BIN)
	@fail=0; for t in $(UNIT_BIN); do $$t || fail=1; done; exit $$fail

# Reports rather than fails when the module is absent: `make test` on a machine
# without the module loaded should say so, not pretend the suite failed.
integration: $(INT_BIN)
	@if [ ! -e /dev/kvault ]; then \
		echo "== integration: skipped (/dev/kvault absent; run 'sudo make load')"; \
	else \
		fail=0; for t in $(INT_BIN); do $$t || fail=1; done; exit $$fail; \
	fi

system: $(SYS_BIN)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "== system: skipped (needs root; run 'sudo make test')"; \
	else \
		fail=0; for t in $(SYS_BIN); do $$t || fail=1; done; exit $$fail; \
	fi

# Reported, not asserted: a throughput number is not a pass/fail result, so it
# is not part of `make run`.
bench: $(BENCH_BIN)
	@for b in $(BENCH_BIN); do $$b; done

clean:
	rm -rf $(BUILD)

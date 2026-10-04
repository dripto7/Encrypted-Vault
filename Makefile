# KVault top-level Makefile
#
#   make            - build the kernel module and the user-space tools
#   make driver     - kvault.ko only
#   make user       - vaultctl + simulator only
#   make load       - insmod with a udev-created device node
#   make unload     - rmmod
#   make test       - build and run the test suites
#
# KDIR defaults to the running kernel's build tree. Point it elsewhere to
# cross-build against a different kernel:
#   make driver KDIR=/lib/modules/6.18.9+kali-amd64/build

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

CXX       ?= g++
CXXFLAGS  ?= -std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Iinclude -Isrc -Isrc/client
LDLIBS    ?= -lcrypto -lpthread

BUILD     := build
BIN       := $(BUILD)/bin

CLIENT_SRC := $(wildcard src/client/*.cpp)
CLI_SRC    := $(wildcard src/cli/*.cpp)
SIM_SRC    := $(wildcard src/sim/*.cpp)
TOOLS_SRC  := $(wildcard src/tools/*.cpp)
CLIENT_OBJ := $(CLIENT_SRC:%.cpp=$(BUILD)/%.o)
CLI_OBJ    := $(CLI_SRC:%.cpp=$(BUILD)/%.o)
SIM_OBJ    := $(SIM_SRC:%.cpp=$(BUILD)/%.o)
TOOLS_OBJ  := $(TOOLS_SRC:%.cpp=$(BUILD)/%.o)

.PHONY: all driver user clean load unload test lint

all: driver user

driver:
	$(MAKE) -C $(KDIR) M=$(PWD)/driver modules

user: $(BIN)/vaultctl $(BIN)/kvsim $(BIN)/kvsetup

$(BIN)/vaultctl: $(CLIENT_OBJ) $(CLI_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

$(BIN)/kvsim: $(CLIENT_OBJ) $(SIM_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

# kvsetup links nothing from the client: it only creates accounts.
$(BIN)/kvsetup: $(TOOLS_OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# The udev rule is installed before the module is loaded, because the rule is
# what gives the two device nodes their different groups - without it they are
# root-only 0600 and nothing the simulator does can reach them.
# The groups themselves come from kvsetup, so that runs first.
load: driver user
	@if ! getent group kvault >/dev/null; then \
		echo "creating the kvault/kvaudit groups and test users"; \
		sudo $(BIN)/kvsetup >/dev/null; \
	fi
	sudo cp scripts/99-kvault.rules /etc/udev/rules.d/
	sudo udevadm control --reload
	sudo insmod driver/kvault.ko
	@sudo udevadm settle || true
	@ls -l /dev/kvault /dev/kvault_audit

unload:
	-sudo rmmod kvault

test: user
	$(MAKE) -C tests run

lint:
	cppcheck --enable=warning,style --std=c++17 -Iinclude src/ 2>&1 | tail -40

clean:
	-$(MAKE) -C $(KDIR) M=$(PWD)/driver clean
	rm -rf $(BUILD)

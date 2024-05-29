

MODULE=cheri_alu

# root path
ROOT_PATH    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# source file list
src-list     := tb.list
src          := $(shell xargs printf '\n%s' < $(src-list)  | cut -b 1-)
# verilator version
verilator      ?= /home/ninolomata/Desktop/Development/cva6-development/cva6/corev_apu/tb/tb_cheri_alu/verilator/bin/verilator
# verilator lib
ver-library    ?= work-ver
verilator_threads := 1
# additional definess
VM_TRACE ?= 1
# Verilator simulator flags
VCD_DUMP ?= "$(VER_BUILD_DIR)dump.vcd"

# Setup Verilator build directory
VER_BUILD_DIR ?= $(ROOT_PATH)$(ver-library)/
# Setup Verilator logs directory
VER_LOGS_DIR ?= $(ROOT_PATH)logs/

#Gtest Setup
GTEST_GIT := https://github.com/google/googletest.git
GTEST_BRANCH := v1.10.x
GTEST_DIR := $(VER_BUILD_DIR)gtest/
GTEST_BUILD := $(GTEST_DIR)build/
GTEST_DEFINES := -DBUILD_GMOCK=OFF

#Verilator Flags
CFLAGS := -I$(RISCV)/include                            \
          -std=c++14 -I$(root-dir)/corev_apu/tb/dpi     \
		  -I$(GTEST_BUILD)/googletest/include/          \
		  -I/home/ninolomata/Desktop/Development/cva6-development/cva6/corev_apu/tb/tb_cheri_alu/verilator/ \
		  -O3

BUILD_MACROS := -DVL_DEBUG
ifdef VM_TRACE
BUILD_MACROS += -DVM_TRACE
# Verilator simulator flags
VCD_DUMP ?= "$(VER_BUILD_DIR)dump.vcd"
endif 

LDFLAGS := -L$(GTEST_BUILD)/lib -L$(RISCV)/lib          \
           -Wl,-rpath,$(RISCV)/lib 						\
		   -lfesvr                                      \
		   -lpthread									\
		   -lgtest

ifndef RISCV
$(error RISCV not set - please point your RISCV variable to your RISCV installation)
endif

# verilator-specific
verilate_command := $(verilator)                                          \
                    $(src)                                                \
                    --unroll-count 256                                    \
                    -Werror-PINMISSING                                    \
                    -Werror-IMPLICIT                                      \
                    -Wno-fatal                                            \
                    -Wno-PINCONNECTEMPTY                                  \
                    -Wno-ASSIGNDLY                                        \
                    -Wno-DECLFILENAME                                     \
                    -Wno-UNUSED                                           \
                    -Wno-UNOPTFLAT                                        \
                    -Wno-BLKANDNBLK                                       \
                    -Wno-style                                            \
                    --trace --trace-structs                               \
                    -LDFLAGS "$(LDFLAGS)"                                 \
                    -CFLAGS "$(CFLAGS) $(BUILD_MACROS)"                   \
                    -Wall --cc ${ROOT_PATH}/hdl/$(MODULE)_testharness.sv  \
                    --top-module $(MODULE)_testharness                    \
                    --Mdir $(VER_BUILD_DIR) -O3                           \
                    --exe ${ROOT_PATH}/src/$(MODULE)_tb.cpp

# verilator-specific
verilate_lint_command := $(verilator)                                     \
                    $(src)                                                \
					--lint-only                                           \
                    --unroll-count 256                                    \
                    -Werror-PINMISSING                                    \
                    -Werror-IMPLICIT                                      \
                    -Wno-fatal                                            \
                    -Wno-PINCONNECTEMPTY                                  \
                    -Wno-ASSIGNDLY                                        \
                    -Wno-DECLFILENAME                                     \
                    -Wno-UNUSED                                           \
                    -Wno-UNOPTFLAT                                        \
                    -Wno-BLKANDNBLK                                       \
                    -Wno-style                                            \
                    --trace --trace-structs                               \
                    -LDFLAGS "$(LDFLAGS)"                                 \
                    -CFLAGS "$(CFLAGS) $(BUILD_MACROS)"                   \
                    -Wall --cc ${ROOT_PATH}/hdl/$(MODULE)_testharness.sv  \
                    --top-module $(MODULE)_testharness                    \
                    --Mdir $(VER_BUILD_DIR) -O3                           \
                    --exe ${ROOT_PATH}/src/$(MODULE)_tb.cpp

.PHONY:waves
waves: $(VCD_DUMP)
	@echo
	@echo "<----Open $(VCD_DUMP) in GTKWave---->"
	gtkwave $(VCD_DUMP)
	@echo "<----Close GTKWave---->"

$(VCD_DUMP): verilate

.PHONY:verilate
verilate:
	@echo $(VER_LOGS_DIR)
	@echo "<----Building Verilator Model for $(Module)---->"
	$(verilate_command)
	cd $(VER_BUILD_DIR) && $(MAKE) -j${NUM_JOBS} -f V$(MODULE)_testharness.mk
	@mkdir -p $(VER_LOGS_DIR)

.PHONY:runtests
runtests: $(VER_BUILD_DIR)V$(MODULE)_testharness.mk
	@echo
	@echo "<----Running Tests---->"
	@$(VER_BUILD_DIR)V$(MODULE)_testharness
	@echo "<----Finish running Tests---->"

.PHONY:lint
verilator-lint:
	$(verilate_lint_command)


.PHONY:gtest
gtest:
	@echo
	@echo "<----Building GTest Framework---->"
	@rm -rf $(GTEST_DIR)
	@git clone $(GTEST_GIT) $(GTEST_DIR) --depth 1 \
	--branch $(GTEST_BRANCH)
	@mkdir -p $(GTEST_BUILD) && cd $(GTEST_BUILD) && cmake $(GTEST_DIR) $(GTEST_DEFINES) && make
	@echo "<----Finish building GTest Framework---->"

$(VER_BUILD_DIR):
	@echo "<----Generate build directory---->"
	@mkdir -p $(VER_BUILD_DIR)
	@echo "<----Finish generating build directory---->"


.PHONY: clean
clean:
	rm -rf .stamp.*;
	rm -rf $(VER_BUILD_DIR)
	rm -rf $(VER_LOGS_DIR)    
	rm -f tmp/*.ucdb tmp/*.log *.wlf *vstf wlft* *.ucdb
	rm -rf *.vcd

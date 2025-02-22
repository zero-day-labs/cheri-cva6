# Copyright 2025 Bruno Sá and Zero-Day Labs.
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# questa library
library        ?= work
# verilator lib
ver-library    ?= work-ver
# library for DPI
dpi-library    ?= work-dpi
# Top level module to compile
top_level      ?= ariane_tb
# Maximum amount of cycles for a successful simulation run
max_cycles     ?= 10000000
# verilator version
verilator      ?= /media/ninolomata/Nino1/CHERI/TestRIG/riscv-implementations/cva6/tools/verilator/bin/verilator
# traget option
target-options ?=
# additional definess
defines        ?= WT_DCACHE
# root path
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
root-dir := $(abspath $(dir $(mkfile_path))../../..)/

ifndef CVA6_REPO_DIR
$(warning must set CVA6_REPO_DIR to point at the root of CVA6 sources -- doing it for you...)
export CVA6_REPO_DIR = $(abspath $(root-dir))
endif

support_verilator_4 := $(shell ($(verilator) --version | grep '4\.') > /dev/null 2>&1 ; echo $$?)
ifeq ($(support_verilator_4), 0)
	verilator_threads := 2
endif
verilator_threads := 1
ifndef RISCV
$(error RISCV not set - please point your RISCV variable to your RISCV installation)
endif

SPIKE_INSTALL_DIR     ?= $(root-dir)/tools/spike

target     ?= cv64a6_imafdch_sv39_rvfi_dii
ifeq ($(target), cv64a6_imafdch_sv39_rvfi_dii)
	XLEN ?= 64
else
	XLEN ?= 32
endif
ifndef TARGET_CFG
	export TARGET_CFG = $(target)
endif

# HPDcache directory
HPDCACHE_DIR ?= $(CVA6_REPO_DIR)/core/cache_subsystem/hpdcache
export HPDCACHE_DIR

# Sources
# Package files -> compile first
ariane_pkg := \
              corev_apu/tb/ariane_axi_pkg.sv                                            \
              corev_apu/tb/axi_intf.sv                                                  \
              corev_apu/register_interface/src/reg_intf.sv                              \
              corev_apu/tb/ariane_soc_pkg.sv                                            \
			  vendor/zero-day/axi_tagcontroller/src/common_cells/src/cb_filter_pkg.sv   \
			  vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_pkg.sv          \
			  vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_reg_pkg.sv      \
			  vendor/zero-day/axi_tagcontroller/include/axi_tagctrl_pkg.sv              \
              corev_apu/riscv-dbg/src/dm_pkg.sv                                         \
              corev_apu/tb/ariane_axi_soc_pkg.sv
ariane_pkg := $(addprefix $(root-dir), $(ariane_pkg))

# utility modules
util := core/include/instr_tracer_pkg.sv                              \
        common/local/util/instr_tracer_if.sv                          \
        common/local/util/instr_tracer.sv                             \
        corev_apu/src/tech_cells_generic/src/cluster_clock_gating.sv  \
        corev_apu/tb/common/mock_uart.sv                              \
        common/local/util/sram.sv

util := $(addprefix $(root-dir), $(util))

# Test packages
test_pkg := $(wildcard tb/test/*/*sequence_pkg.sv*) \
			$(wildcard tb/test/*/*_pkg.sv*)

# DPI
 dpi := $(patsubst $(root-dir)/corev_apu/tb/dpi/%.cc, ${dpi-library}/%.o, $(wildcard $(root-dir)/corev_apu/tb/dpi/*.cc))

dpi_hdr := $(wildcard $(root-dir)/corev_apu/tb/dpi/*.h)
#  dpi_hdr := $(addprefix $(root-dir), $(dpi_hdr))

CFLAGS := -I$(QUESTASIM_HOME)/include                                       \
          -I$(VCS_HOME)/include                                             \
          -I$(RISCV)/include                                                \
          -I$(SPIKE_ROOT)/include                                           \
		  -I$(root-dir)/corev_apu/tb/tb_testRig_cheri/src/inc               \
          -I$(root-dir)/corev_apu/tb/tb_testRig_cheri/src/SocketPacketUtils \
          -std=c++11 -I$(root-dir)/corev_apu/tb/dpi -O3

# this list contains the standalone components
src :=  $(root-dir)/core/include/$(target)_config_pkg.sv                                                         \
        $(if $(spike-tandem),$(root-dir)/verif/tb/core/uvma_core_cntrl_pkg.sv)                                   \
        $(if $(spike-tandem),$(root-dir)/verif/tb/core/uvma_cva6pkg_utils_pkg.sv)                                \
        $(if $(spike-tandem),$(root-dir)/verif/tb/core/uvma_rvfi_pkg.sv)                                         \
        $(if $(spike-tandem),$(root-dir)/verif/tb/core/uvmc_rvfi_reference_model_pkg.sv)                         \
        $(if $(spike-tandem),$(root-dir)/verif/tb/core/uvmc_rvfi_scoreboard_pkg.sv)                              \
        $(if $(spike-tandem),$(root-dir)/corev_apu/tb/common/spike.sv)                                           \
        $(root-dir)/corev_apu/src/ariane.sv                                                                      \
        $(wildcard $(root-dir)/corev_apu/bootrom/*.sv)                                                           \
        $(wildcard $(root-dir)/corev_apu/clint/*.sv)                                                             \
        $(wildcard $(root-dir)/corev_apu/fpga/src/axi2apb/src/*.sv)                                              \
        $(wildcard $(root-dir)/corev_apu/fpga/src/apb_timer/*.sv)                                                \
        $(wildcard $(root-dir)/corev_apu/fpga/src/axi_slice/src/*.sv)                                            \
        $(wildcard $(root-dir)/corev_apu/src/axi_riscv_atomics/src/*.sv)                                         \
        $(wildcard $(root-dir)/corev_apu/axi_mem_if/src/*.sv)                                                    \
        $(root-dir)/corev_apu/rv_plic/rtl/rv_plic_target.sv                                                      \
        $(root-dir)/corev_apu/rv_plic/rtl/rv_plic_gateway.sv                                                     \
        $(root-dir)/corev_apu/rv_plic/rtl/plic_regmap.sv                                                         \
        $(root-dir)/corev_apu/rv_plic/rtl/plic_top.sv                                                            \
        $(root-dir)/corev_apu/riscv-dbg/src/dmi_cdc.sv                                                           \
        $(root-dir)/corev_apu/riscv-dbg/src/dmi_jtag.sv                                                          \
        $(root-dir)/corev_apu/riscv-dbg/src/dmi_jtag_tap.sv                                                      \
        $(root-dir)/corev_apu/riscv-dbg/src/dm_csrs.sv                                                           \
        $(root-dir)/corev_apu/riscv-dbg/src/dm_mem.sv                                                            \
        $(root-dir)/corev_apu/riscv-dbg/src/dm_sba.sv                                                            \
        $(root-dir)/corev_apu/riscv-dbg/src/dm_top.sv                                                            \
        $(root-dir)/corev_apu/riscv-dbg/debug_rom/debug_rom.sv                                                   \
        $(root-dir)/corev_apu/register_interface/src/apb_to_reg.sv                                               \
		$(root-dir)/corev_apu/register_interface/vendor/lowrisc_opentitan/src/prim_subreg.sv                     \
		$(root-dir)/corev_apu/register_interface/vendor/lowrisc_opentitan/src/prim_subreg_arb.sv                 \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_multicut.sv                                                 \
        $(root-dir)/vendor/pulp-platform/common_cells/src/rstgen_bypass.sv                                       \
        $(root-dir)/vendor/pulp-platform/common_cells/src/rstgen.sv                                              \
        $(root-dir)/vendor/pulp-platform/common_cells/src/addr_decode.sv                                         \
	    $(root-dir)/vendor/pulp-platform/common_cells/src/stream_register.sv                                     \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_cut.sv                                                      \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_join.sv                                                     \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_delayer.sv                                                  \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_to_axi_lite.sv                                              \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_id_prepend.sv                                               \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_atop_filter.sv                                              \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_err_slv.sv                                                  \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_mux.sv                                                      \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_demux.sv                                                    \
        $(root-dir)/vendor/pulp-platform/axi/src/axi_xbar.sv                                                     \
		$(root-dir)/vendor/pulp-platform/axi/src/axi_isolate.sv                                                  \
        $(root-dir)/vendor/pulp-platform/common_cells/src/cdc_2phase.sv                                          \
        $(root-dir)/vendor/pulp-platform/common_cells/src/spill_register_flushable.sv                            \
        $(root-dir)/vendor/pulp-platform/common_cells/src/spill_register.sv                                      \
        $(root-dir)/vendor/pulp-platform/common_cells/src/deprecated/fifo_v1.sv                                  \
        $(root-dir)/vendor/pulp-platform/common_cells/src/deprecated/fifo_v2.sv                                  \
        $(root-dir)/vendor/pulp-platform/common_cells/src/stream_delay.sv                                        \
        $(root-dir)/vendor/pulp-platform/common_cells/src/lfsr_16bit.sv                                          \
		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/common_cells/src/cb_filter.sv                          \
		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/common_cells/src/sub_per_hash.sv                       \
        $(root-dir)/vendor/pulp-platform/tech_cells_generic/src/deprecated/cluster_clk_cells.sv                  \
        $(root-dir)/vendor/pulp-platform/tech_cells_generic/src/deprecated/pulp_clk_cells.sv                     \
        $(root-dir)/vendor/pulp-platform/tech_cells_generic/src/rtl/tc_clk.sv                                    \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_burst_cutter.sv                    \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_data_way.sv                        \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_merge_unit.sv                      \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_read_unit.sv                       \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_reg_top.sv                         \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_write_unit.sv                      \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/eviction_refill/axi_llc_ax_master.sv       \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/eviction_refill/axi_llc_r_master.sv        \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/eviction_refill/axi_llc_w_master.sv        \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/hit_miss_detect/axi_llc_evict_box.sv       \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/hit_miss_detect/axi_llc_lock_box_bloom.sv  \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/hit_miss_detect/axi_llc_miss_counters.sv   \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/hit_miss_detect/axi_llc_tag_pattern_gen.sv \
     	$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_data_way.sv                                \
        $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_ways.sv                                    \
		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_chan_splitter.sv                   \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_evict_unit.sv                      \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_refill_unit.sv                     \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_ways.sv                            \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc_tag_store.sv                                   \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagc_read_unit.sv                                  \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagc_write_unit.sv                                 \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_ax.sv                                      \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_config.sv                                  \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_r.sv                                       \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_w.sv                                       \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_config.sv                          \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/src/axi_llc_hit_miss.sv                        \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_top.sv                                     \
  		$(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_tagctrl_reg_wrap.sv                                \
        $(root-dir)/corev_apu/tb/ariane_testharness.sv                                                           \
        $(root-dir)/corev_apu/tb/tb_testRig_cheri/hdl/ariane_testharness_dii.sv                                  \
		$(root-dir)/corev_apu/tb/cva6_cheri_tag_mem.sv                                                           \
        $(root-dir)/corev_apu/tb/ariane_peripherals.sv                                                           \
        $(root-dir)/corev_apu/tb/rvfi_tracer.sv                                                                  \
        $(root-dir)/corev_apu/tb/common/uart.sv                                                                  \
        $(root-dir)/corev_apu/tb/common/SimDTM.sv                                                                \
        $(root-dir)/corev_apu/tb/common/SimJTAG.sv                                                               \
        $(root-dir)/corev_apu/tb/tb_testRig_cheri/hdl/ariane_testharness_dii.sv

copro_src := core/cvxif_example/include/cvxif_instr_pkg.sv \
             $(wildcard core/cvxif_example/*.sv)
copro_src := $(addprefix $(root-dir), $(copro_src))

uart_src := $(wildcard corev_apu/fpga/src/apb_uart/src/*.vhd)
uart_src := $(addprefix $(root-dir), $(uart_src))

# look for testbenches
tbs := corev_apu/tb/ariane_tb.sv corev_apu/tb/ariane_testharness.sv core/cva6_rvfi.sv corev_apu/tb/tb_testRig_cheri/hdl/ariane_testharness_dii.sv

tbs := $(addprefix $(root-dir), $(tbs))

# Search here for include files (e.g.: non-standalone components)
incdir := $(root-dir)/vendor/pulp-platform/common_cells/include/ $(CVA6_REPO_DIR)/vendor/pulp-platform/axi/include/ \
		  $(root-dir)/vendor/zero-day/axi_tagcontroller/include/                                                    \
		  $(root-dir)/vendor/zero-day/axi_tagcontroller/src/axi_llc/include/                                        \
          $(root-dir)/corev_apu/register_interface/include/ $(CVA6_REPO_DIR)/corev_apu/tb/common/                   \
          $(root-dir)/vendor/pulp-platform/axi/include/                                                             \
          $(root-dir)/verif/core-v-verif/lib/uvm_agents/uvma_rvfi/                                                  \
          $(root-dir)/verif/core-v-verif/lib/uvm_components/uvmc_rvfi_reference_model/                              \
          $(root-dir)/verif/core-v-verif/lib/uvm_components/uvmc_rvfi_scoreboard/                                   \
          $(root-dir)/verif/core-v-verif/lib/uvm_agents/uvma_core_cntrl/                                            \
          $(root-dir)/verif/tb/core/                                                                                \
          $(root-dir)/core/include/

# Iterate over all include directories and write them with +incdir+ prefixed
# +incdir+ works for Verilator and QuestaSim
list_incdir := $(foreach dir, ${incdir}, +incdir+$(dir))

# verilator-specific
verilate_command := $(verilator) --no-timing $(root-dir)/verilator_config.vlt                                    \
                    -f $(root-dir)/core/Flist.cva6                                                               \
                    $(root-dir)/core/cva6_rvfi.sv                                                                \
                    $(filter-out %.vhd, $(ariane_pkg))                                                           \
					$(filter-out core/fpu_wrap.sv, $(filter-out %.vhd, $(filter-out %_config_pkg.sv, $(src))))   \
                    +define+RVFI_TRACE=1+DII=1+VM_TRACE=$(DEBUG)                                                 \
                    $(root-dir)/common/local/util/sram.sv                                                        \
                    $(root-dir)/corev_apu/tb/common/mock_uart.sv                                                 \
                    +incdir+$(root-dir)/corev_apu/axi_node                                                       \
                    $(if $(verilator_threads), --threads $(verilator_threads))                                   \
                    --unroll-count 256                                                                           \
                    -Werror-PINMISSING                                                                           \
                    -Werror-IMPLICIT                                                                             \
                    -Wno-fatal                                                                                   \
                    -Wno-PINCONNECTEMPTY                                                                         \
                    -Wno-ASSIGNDLY                                                                               \
                    -Wno-DECLFILENAME                                                                            \
                    -Wno-UNUSED                                                                                  \
                    -Wno-UNOPTFLAT                                                                               \
                    -Wno-BLKANDNBLK                                                                              \
                    -Wno-style                                                                                   \
                    $(if $(DEBUG), --trace --trace-structs )                                                     \
                    -LDFLAGS "-L$(RISCV)/lib -L$(SPIKE_INSTALL_DIR)/lib -Wl,-rpath,$(RISCV)/lib -Wl,-rpath,$(SPIKE_INSTALL_DIR)/lib -lfesvr$(if $(PROFILE), -g -pg,) $(if $(DROMAJO), -L../corev_apu/tb/dromajo/src -ldromajo_cosim,) -lpthread" \
                    -CFLAGS "$(CFLAGS)$(if $(PROFILE), -g -pg,) $(if $(DROMAJO), -DDROMAJO=1,) -DVL_DEBUG"       \
                    -Wall --cc  --vpi                                                                            \
                    $(list_incdir) --top-module ariane_testharness_dii                                           \
					--threads-dpi none 																			 \
                    --Mdir $(ver-library) -O3                                                                    \
                    --exe ${root-dir}/corev_apu/tb/tb_testRig_cheri/src/cva6_dii_toplevel.cpp ${root-dir}/corev_apu/tb/tb_testRig_cheri/src/SocketPacketUtils/socket_packet_utils.c ${root-dir}/corev_apu/tb/dpi/SimDTM.cc ${root-dir}/corev_apu/tb/dpi/SimJTAG.cc      \
                    ${root-dir}/corev_apu/tb/dpi/remote_bitbang.cc ${root-dir}/corev_apu/tb/dpi/msim_helper.cc

# User Verilator, at some point in the future this will be auto-generated
verilate:
	@echo "[Verilator] Building Model for TestRig CHERI"
	@echo "$(root-dir)"
	$(verilate_command)
	cd $(ver-library) && $(MAKE) -j${NUM_JOBS} -f Variane_testharness_dii.mk

clean:
	rm -rf $(riscv-torture-dir)/output/test*
	rm -rf $(library)/ $(dpi-library)/ $(ver-library)/
	rm -f tmp/*.ucdb tmp/*.log *.wlf *vstf wlft* *.ucdb

.PHONY:
	build sim sim-verilate clean                                              \
	$(riscv-asm-tests) $(addsuffix _verilator,$(riscv-asm-tests))             \
	$(riscv-benchmarks) $(addsuffix _verilator,$(riscv-benchmarks))           \
	check-benchmarks check-asm-tests                                          \
	torture-gen torture-itest torture-rtest                                   \
	run-torture run-torture-verilator check-torture check-torture-verilator

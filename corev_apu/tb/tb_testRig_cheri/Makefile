# Author: Florian Zaruba, ETH Zurich
# Date: 03/19/2017
# Description: Makefile for linting and testing Ariane.

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
verilator      ?= verilator
# traget option
target-options ?=
# additional definess
defines        ?= WT_DCACHE
# root path
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
root-dir := /home/ninolomata/Desktop/Development/cva6-development/cva6/

support_verilator_4 := $(shell ($(verilator) --version | grep '4\.') > /dev/null 2>&1 ; echo $$?)
ifeq ($(support_verilator_4), 0)
	verilator_threads := 2
endif
verilator_threads := 1
ifndef RISCV
$(error RISCV not set - please point your RISCV variable to your RISCV installation)
endif

# Sources
# Package files
ariane_pkg += core/include/cv64a6_imacfd_sv39_config_pkg.sv		     \
			  core/include/riscv_pkg.sv                              \
			  core/include/cva6_cheri_pkg.sv                         \
              corev_apu/riscv-dbg/src/dm_pkg.sv                      \
              core/include/ariane_pkg.sv                             \
              core/include/ariane_rvfi_pkg.sv                        \
              core/include/std_cache_pkg.sv                          \
              core/include/wt_cache_pkg.sv                           \
              corev_apu/axi/src/axi_pkg.sv                           \
              corev_apu/register_interface/src/reg_intf.sv           \
              corev_apu/register_interface/src/reg_intf_pkg.sv       \
              core/include/axi_intf.sv                               \
              corev_apu/tb/rvfi_pkg.sv                               \
              corev_apu/tb/ariane_soc_pkg.sv                         \
              corev_apu/tb/ariane_axi_soc_pkg.sv                     \
              core/include/ariane_axi_pkg.sv                         \
              core/fpu/src/fpnew_pkg.sv                              \
              core/fpu/src/fpu_div_sqrt_mvp/hdl/defs_div_sqrt_mvp.sv
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

CFLAGS := -I$(QUESTASIM_HOME)/include         \
          -I$(VCS_HOME)/include \
          -I$(RISCV)/include                  \
          -I$(SPIKE_ROOT)/include             \
		  -I$(root-dir)/corev_apu/tb/tb_testRig_cheri/src/inc \
          -std=c++11 -I$(root-dir)/corev_apu/tb/dpi -O3

# this list contains the standalone components
src :=  $(filter-out ${root-dir}/core/ariane_regfile.sv, $(wildcard ${root-dir}/core/*.sv))                  \
        $(filter-out ${root-dir}/core/fpu/src/fpnew_pkg.sv, $(wildcard ${root-dir}/core/fpu/src/*.sv))       \
        $(filter-out ${root-dir}/core/fpu/src/fpu_div_sqrt_mvp/hdl/defs_div_sqrt_mvp.sv,         \
        $(wildcard ${root-dir}/core/fpu/src/fpu_div_sqrt_mvp/hdl/*.sv))                          \
        $(wildcard ${root-dir}/core/frontend/*.sv)                                               \
        $(filter-out ${root-dir}/core/cache_subsystem/std_no_dcache.sv,                          \
        $(wildcard ${root-dir}/core/cache_subsystem/*.sv))                                       \
        $(wildcard ${root-dir}/corev_apu/bootrom/*.sv)                                           \
        $(wildcard ${root-dir}/corev_apu/clint/*.sv)                                             \
        $(wildcard ${root-dir}/corev_apu/fpga/src/axi2apb/src/*.sv)                              \
        $(wildcard ${root-dir}/corev_apu/fpga/src/apb_timer/*.sv)                                \
        $(wildcard ${root-dir}/corev_apu/fpga/src/axi_slice/src/*.sv)                            \
        $(wildcard ${root-dir}/corev_apu/axi_node/src/*.sv)                                      \
        $(wildcard ${root-dir}/corev_apu/src/axi_riscv_atomics/src/*.sv)                         \
        $(wildcard ${root-dir}/corev_apu/axi_mem_if/src/*.sv)                                    \
        $(wildcard ${root-dir}/core/pmp/src/*.sv)                                                \
		$(wildcard ${root-dir}core/mmu_sv39/*.sv)											     \
        ${root-dir}/corev_apu/rv_plic/rtl/rv_plic_target.sv                                      \
        ${root-dir}/corev_apu/rv_plic/rtl/rv_plic_gateway.sv                                     \
        ${root-dir}/corev_apu/rv_plic/rtl/plic_regmap.sv                                         \
        ${root-dir}/corev_apu/rv_plic/rtl/plic_top.sv                                            \
        ${root-dir}/corev_apu/riscv-dbg/src/dmi_cdc.sv                                           \
        ${root-dir}/corev_apu/riscv-dbg/src/dmi_jtag.sv                                          \
        ${root-dir}/corev_apu/riscv-dbg/src/dmi_jtag_tap.sv                                      \
        ${root-dir}/corev_apu/riscv-dbg/src/dm_csrs.sv                                           \
        ${root-dir}/corev_apu/riscv-dbg/src/dm_mem.sv                                            \
        ${root-dir}/corev_apu/riscv-dbg/src/dm_sba.sv                                            \
        ${root-dir}/corev_apu/riscv-dbg/src/dm_top.sv                                            \
        ${root-dir}/corev_apu/riscv-dbg/debug_rom/debug_rom.sv                                   \
        ${root-dir}/corev_apu/register_interface/src/apb_to_reg.sv                               \
        ${root-dir}/corev_apu/axi/src/axi_multicut.sv                                            \
        ${root-dir}/common/submodules/common_cells/src/deprecated/generic_fifo.sv                \
        ${root-dir}/common/submodules/common_cells/src/deprecated/pulp_sync.sv                   \
        ${root-dir}/common/submodules/common_cells/src/deprecated/find_first_one.sv              \
        ${root-dir}/common/submodules/common_cells/src/rstgen_bypass.sv                          \
        ${root-dir}/common/submodules/common_cells/src/rstgen.sv                                 \
        ${root-dir}/common/submodules/common_cells/src/stream_mux.sv                             \
        ${root-dir}/common/submodules/common_cells/src/stream_demux.sv                           \
        ${root-dir}/common/submodules/common_cells/src/exp_backoff.sv                            \
        ${root-dir}/common/local/util/axi_master_connect.sv                                      \
        ${root-dir}/common/local/util/axi_slave_connect.sv                                       \
        ${root-dir}/common/local/util/axi_master_connect_rev.sv                                  \
        ${root-dir}/common/local/util/axi_slave_connect_rev.sv                                   \
        ${root-dir}/corev_apu/axi/src/axi_cut.sv                                                 \
        ${root-dir}/corev_apu/axi/src/axi_join.sv                                                \
        ${root-dir}/corev_apu/axi/src/axi_delayer.sv                                             \
        ${root-dir}/corev_apu/axi/src/axi_to_axi_lite.sv                                         \
        ${root-dir}/corev_apu/fpga-support/rtl/SyncSpRamBeNx64.sv                                \
        ${root-dir}/common/submodules/common_cells/src/unread.sv                                 \
        ${root-dir}/common/submodules/common_cells/src/sync.sv                                   \
        ${root-dir}/common/submodules/common_cells/src/cdc_2phase.sv                             \
        ${root-dir}/common/submodules/common_cells/src/spill_register.sv                         \
        ${root-dir}/common/submodules/common_cells/src/sync_wedge.sv                             \
        ${root-dir}/common/submodules/common_cells/src/edge_detect.sv                            \
        ${root-dir}/common/submodules/common_cells/src/stream_arbiter.sv                         \
        ${root-dir}/common/submodules/common_cells/src/stream_arbiter_flushable.sv               \
        ${root-dir}/common/submodules/common_cells/src/deprecated/fifo_v1.sv                     \
        ${root-dir}/common/submodules/common_cells/src/deprecated/fifo_v2.sv                     \
        ${root-dir}/common/submodules/common_cells/src/fifo_v3.sv                                \
        ${root-dir}/common/submodules/common_cells/src/lzc.sv                                    \
        ${root-dir}/common/submodules/common_cells/src/popcount.sv                               \
        ${root-dir}/common/submodules/common_cells/src/rr_arb_tree.sv                            \
        ${root-dir}/common/submodules/common_cells/src/deprecated/rrarbiter.sv                   \
        ${root-dir}/common/submodules/common_cells/src/stream_delay.sv                           \
        ${root-dir}/common/submodules/common_cells/src/lfsr.sv                                   \
        ${root-dir}/common/submodules/common_cells/src/lfsr_8bit.sv                              \
        ${root-dir}/common/submodules/common_cells/src/lfsr_16bit.sv                             \
        ${root-dir}/common/submodules/common_cells/src/delta_counter.sv                          \
        ${root-dir}/common/submodules/common_cells/src/counter.sv                                \
        ${root-dir}/common/submodules/common_cells/src/shift_reg.sv                              \
        ${root-dir}/corev_apu/src/tech_cells_generic/src/pulp_clock_gating.sv                    \
        ${root-dir}/corev_apu/src/tech_cells_generic/src/cluster_clock_inverter.sv               \
        ${root-dir}/corev_apu/src/tech_cells_generic/src/pulp_clock_mux2.sv                      \
		${root-dir}/corev_apu/tb/cva6_cheri_tag_mem.sv                                           \
        ${root-dir}/corev_apu/tb/ariane_peripherals.sv                                           \
        ${root-dir}/corev_apu/tb/rvfi_tracer.sv                                                  \
        ${root-dir}/corev_apu/tb/common/uart.sv                                                  \
        ${root-dir}/corev_apu/tb/common/SimDTM.sv                                                \
        ${root-dir}/corev_apu/tb/common/SimJTAG.sv 												 \
		${root-dir}/corev_apu/tb/tb_testRig_cheri/hdl/ariane_testharness_dii.sv


uart_src := $(wildcard ${root-dir}/corev_apu/fpga/src/apb_uart/src/*.vhd)

# look for testbenches
tbs := ${root-dir}/corev_apu/tb/tb_testRig_cheri/hdl/ariane_testharness_dii.sv

# Search here for include files (e.g.: non-standalone components)
incdir := ${root-dir}/common/submodules/common_cells/include/

# Compile and sim flags
compile_flag     += +cover=bcfst+/dut -incr -64 -nologo -quiet -suppress 13262 -permissive +define+$(defines)
uvm-flags        += +UVM_NO_RELNOTES +UVM_VERBOSITY=LOW
questa-flags     += -t 1ns -64 -coverage -classdebug $(gui-sim) $(QUESTASIM_FLAGS)
compile_flag_vhd += -64 -nologo -quiet -2008

# Iterate over all include directories and write them with +incdir+ prefixed
# +incdir+ works for Verilator and QuestaSim
list_incdir := $(foreach dir, ${incdir}, +incdir+$(dir))

# verilator-specific
verilate_command := $(verilator)                                                                                 \
                    $(filter-out %.vhd, $(ariane_pkg))                                                           \
					$(filter-out %.vhd, $(src)) 	                 \
                    +define+$(defines) -DRVFI_TRACE=1 -DDII=1                                                    \
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
                    --trace --trace-structs                                                                      \
                    -LDFLAGS "-L$(RISCV)/lib -L$(SPIKE_ROOT)/lib -Wl,-rpath,$(RISCV)/lib -Wl,-rpath,$(SPIKE_ROOT)/lib -lfesvr$(if $(PROFILE), -g -pg,) $(if $(DROMAJO), -L../corev_apu/tb/dromajo/src -ldromajo_cosim,) -lpthread" \
                    -CFLAGS "$(CFLAGS)$(if $(PROFILE), -g -pg,) $(if $(DROMAJO), -DDROMAJO=1,) -DVL_DEBUG"       \
                    -Wall --cc  --vpi                                                                            \
                    $(list_incdir) --top-module ariane_testharness_dii                                             \
					--threads-dpi none 																			 \
                    --Mdir $(ver-library) -O3                                                                    \
                    --exe ${root-dir}/corev_apu/tb/ariane_tb.cpp ${root-dir}/corev_apu/tb/tb_testRig_cheri/src/socket.c ${root-dir}/corev_apu/tb/dpi/SimDTM.cc ${root-dir}/corev_apu/tb/dpi/SimJTAG.cc      \
                    ${root-dir}/corev_apu/tb/dpi/remote_bitbang.cc ${root-dir}/corev_apu/tb/dpi/msim_helper.cc

# User Verilator, at some point in the future this will be auto-generated
verilate:
	@echo "[Verilator] Building Model for TestRig CHERI"
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

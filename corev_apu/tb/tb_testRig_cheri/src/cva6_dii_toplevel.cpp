// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at

//   http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "verilator.h"
#include "verilated.h"
#include "Variane_testharness_dii.h"
#if (VERILATOR_VERSION_INTEGER >= 5000000)
  // Verilator v5 adds $root wrapper that provides rootp pointer.
  #include "Variane_testharness_dii___024root.h"
#endif
#if VM_TRACE_FST
#include "verilated_fst_c.h"
#else
#include "verilated_vcd_c.h"
#endif
#include "Variane_testharness_dii__Dpi.h"

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <getopt.h>
#include <chrono>
#include <ctime>
#include <signal.h>
#include <unistd.h>
#include <vector>

#include <fesvr/dtm.h>
#include <fesvr/htif_hexwriter.h>
#include <fesvr/elfloader.h>
#include "remote_bitbang.h"
#include <socket_packet_utils.h>

// This software is heavily based on Rocket Chip
// Checkout this awesome project:
// https://github.com/freechipsproject/rocket-chip/
#define DII 1

// This is a 64-bit integer to reduce wrap over issues and
// allow modulus.  You can also use a double, if you wish.
static vluint64_t main_time = 0;

static const char *verilog_plusargs[] = {"jtag_rbb_enable", "time_out", "debug_disable"};

#ifndef DROMAJO
extern dtm_t* dtm;
extern remote_bitbang_t * jtag;

void handle_sigterm(int sig) {
  dtm->stop();
}
#endif

#ifdef DII
  struct RVFI_DII_Execution_Packet {
    std::uint64_t rvfi_order : 64;      // [00 - 07] Instruction number:      INSTRET value after completion.
    std::uint64_t rvfi_pc_rdata : 64;   // [08 - 15] PC before instr:         PC for current instruction
    std::uint64_t rvfi_pc_wdata : 64;   // [16 - 23] PC after instr:          Following PC - either PC + 4 or jump/trap target.
    std::uint64_t rvfi_insn : 64;       // [24 - 31] Instruction word:        32-bit command value.
    std::uint64_t rvfi_rs1_data : 64;   // [32 - 39] Read register values:    Values as read from registers named
    std::uint64_t rvfi_rs2_data : 64;   // [40 - 47]                          above. Must be 0 if register ID is 0.
    std::uint64_t rvfi_rd_wdata : 64;   // [48 - 55] Write register value:    MUST be 0 if rd_ is 0.
    std::uint64_t rvfi_mem_addr : 64;   // [56 - 63] Memory access addr:      Points to byte address (aligned if define
                                        //                                      is set). *Should* be straightforward.
                                        //                                      0 if unused.
    std::uint64_t rvfi_mem_rdata : 64;  // [64 - 71] Read data:               Data read from mem_addr (i.e. before write)
    std::uint64_t rvfi_mem_wdata : 64;  // [72 - 79] Write data:              Data written to memory by this command.
    std::uint8_t rvfi_mem_rmask : 8;    // [80]      Read mask:               Indicates valid bytes read. 0 if unused.
    std::uint8_t rvfi_mem_wmask : 8;    // [81]      Write mask:              Indicates valid bytes written. 0 if unused.
    std::uint8_t rvfi_rs1_addr : 8;     // [82]      Read register addresses: Can be arbitrary when not used,
    std::uint8_t rvfi_rs2_addr : 8;     // [83]                          otherwise set as decoded.
    std::uint8_t rvfi_rd_addr : 8;      // [84]      Write register address:  MUST be 0 if not used.
    std::uint8_t rvfi_trap : 8;         // [85] Trap indicator:          Invalid decode, misaligned access or
                                        //                                      jump command to misaligned address.
    std::uint8_t rvfi_halt : 8;         // [86] Halt indicator:          Marks the last instruction retired 
                                        //                                      before halting execution.
    std::uint8_t rvfi_intr : 8;         // [87] Trap handler:            Set for first instruction in trap handler.     
};

struct RVFI_DII_Instruction_Packet {
    std::uint32_t dii_insn : 32;      // [0 - 3] Instruction word: 32-bit instruction or command. The lower 16-bits
                                      // may decode to a 16-bit compressed instruction.
    std::uint16_t dii_time : 16;      // [5 - 4] Time to inject token.  The difference between this and the previous
                                      // instruction time gives a delay before injecting this instruction.
                                      // This can be ignored for models but gives repeatability for implementations
                                      // while shortening counterexamples.
    std::uint8_t dii_cmd : 8;         // [6] This token is a trace command.  For example, reset device under test.
    std::uint8_t padding : 8;         // [7]
};

#endif

extern "C" void read_elf(const char* filename);
extern "C" char get_section (long long* address, long long* len);
extern "C" void read_section_void(long long address, void * buffer, uint64_t size = 0);

void PrintInstTrace(RVFI_DII_Instruction_Packet* packet){
  std::cout << "<------Start instruction trace------>" << std::endl;
  std::cout << "cmd: " << ((packet->dii_cmd == 0) ? "End of Trace" : "Instruction")  << std::endl;
  std::cout << "time: " << (int) packet->dii_time << std::endl;
  std::cout << "insn: " << std::hex << packet->dii_insn << std::endl;
  std::cout << "<------Finish instruction trace------>" << std::endl;
}

void PrintExecTrace(RVFI_DII_Execution_Packet* packet){
  std::cout << "<------Start execution trace------>" << std::endl;
  std::cout << "order: " << (int) packet->rvfi_order << std::endl;      
  std::cout << "pc_rdata: " << std::hex << (int) packet->rvfi_pc_rdata << std::endl;   
  std::cout << "pc_wdata: " << std::hex << (int) packet->rvfi_pc_wdata << std::endl;   
  std::cout << "insn: " << std::hex << (int) packet->rvfi_insn << std::endl;       
  std::cout << "rs1_data: " << std::hex << (int) packet->rvfi_rs1_data << std::endl;   
  std::cout << "rs2_data: " << std::hex << (int) packet->rvfi_rs2_data << std::endl;   
  std::cout << "rd_wdata: " << std::hex << (int) packet->rvfi_rd_wdata << std::endl;   
  std::cout << "mem_addr: " << std::hex << (int) packet->rvfi_mem_addr << std::endl;   
  std::cout << "mem_rdatal: " << std::hex << (int)packet->rvfi_mem_rdata << std::endl; 
  std::cout << "mem_wdatal: " << std::hex << (int) packet->rvfi_mem_wdata << std::endl; 
  std::cout << "mem_rmask: " << std::hex << (int) packet->rvfi_mem_rmask << std::endl;    
  std::cout << "mem_wmask: " << std::hex << (int) packet->rvfi_mem_wmask << std::endl;   
  std::cout << "rs1_addr: " << std::hex << (int) packet->rvfi_rs1_addr << std::endl;    
  std::cout << "rs2_addr: " << std::hex << (int) packet->rvfi_rs2_addr << std::endl;     
  std::cout << "rd_addr: " << std::hex << (int) packet->rvfi_rd_addr << std::endl;      
  std::cout << "trap: " << (int) packet->rvfi_trap << std::endl;        
  std::cout << "halt: " <<  (int) packet->rvfi_halt << std::endl;        
  std::cout << "instr: " << std::hex << (int) packet->rvfi_intr << std::endl;        
  std::cout << "<------Finish execution trace------>" << std::endl;
}

// Routine to fetch intructions from the Vengine
void fetchInstructions(std::vector<RVFI_DII_Instruction_Packet> &instructions, unsigned int &cnt_rec, unsigned long long socket);
RVFI_DII_Execution_Packet readRVFI(Variane_testharness_dii *top);
void returnTrace(std::vector<RVFI_DII_Execution_Packet> &returntrace, unsigned long long socket);
bool readTrace(std::vector<RVFI_DII_Execution_Packet> &returntrace, Variane_testharness_dii *top);

// Called by $time in Verilog converts to double, to match what SystemC does
double sc_time_stamp () {
    return main_time;
}

static void usage(const char * program_name) {
  printf("Usage: %s [EMULATOR OPTION]... [VERILOG PLUSARG]... [HOST OPTION]... BINARY [TARGET OPTION]...\n",
         program_name);
  fputs("\
Run a BINARY on the Ariane emulator.\n\
\n\
Mandatory arguments to long options are mandatory for short options too.\n\
\n\
EMULATOR OPTIONS\n\
  -r, --rbb-port=PORT      Use PORT for remote bit bang (with OpenOCD and GDB) \n\
                           If not specified, a random port will be chosen\n\
                           automatically.\n\
", stdout);
#if VM_TRACE == 0
  fputs("\
\n\
EMULATOR DEBUG OPTIONS (only supported in debug build -- try `make debug`)\n",
        stdout);
#endif
  fputs("\
  -v, --vcd=FILE,          Write vcd trace to FILE (or '-' for stdout)\n\
  -f, --fst=FILE,          Write fst trace to FILE\n\
  -p,                      Print performance statistic at end of test\n\
", stdout);
  // fputs("\n" PLUSARG_USAGE_OPTIONS, stdout);
  fputs("\n" HTIF_USAGE_OPTIONS, stdout);
  printf("\n"
"EXAMPLES\n"
"  - run a bare metal test:\n"
"    %s $RISCV/riscv64-unknown-elf/share/riscv-tests/isa/rv64ui-p-add\n"
"  - run a bare metal test showing cycle-by-cycle information:\n"
"    %s spike-dasm < trace_core_00_0.dasm > trace.out\n"
#if VM_TRACE
"  - run a bare metal test to generate a VCD waveform:\n"
"    %s -v rv64ui-p-add.vcd $RISCV/riscv64-unknown-elf/share/riscv-tests/isa/rv64ui-p-add\n"
"  - run a bare metal test to generate an FST waveform:\n"
"    %s -f rv64ui-p-add.fst $RISCV/riscv64-unknown-elf/share/riscv-tests/isa/rv64ui-p-add\n"
#endif
  , program_name, program_name);
}

// In case we use the DTM we do not want to use the JTAG
// to preload the data but only use the DTM to host fesvr functionality.
class preload_aware_dtm_t : public dtm_t {
  public:
    preload_aware_dtm_t(int argc, char **argv) : dtm_t(argc, argv) {}
    bool is_address_preloaded(addr_t taddr, size_t len) override { return true; }
    // We do not want to reset the hart here as the reset function in `dtm_t` seems to disregard
    // the privilege level and in general does not perform propper reset (despite the name).
    // As all our binaries in preloading will always start at the base of DRAM this should not
    // be such a big problem.
    void reset() {}
};

int main(int argc, char **argv) {
  std::clock_t c_start = std::clock();
  auto t_start = std::chrono::high_resolution_clock::now();
  bool verbose;
  bool perf;
  unsigned random_seed = (unsigned)time(NULL) ^ (unsigned)getpid();
  uint64_t max_cycles = -1;
  int ret = 0;
  bool print_cycles = false;
  // Port numbers are 16 bit unsigned integers.
  uint16_t rbb_port = 0;
#if VM_TRACE
  FILE * vcdfile = NULL;
  char * fst_fname = NULL;
  uint64_t start = 0;
#endif
  char ** htif_argv = NULL;
  int verilog_plusargs_legal = 1;
#if DII
  char* socket_name = NULL;
  int socket_default_port = -1;
#endif

  while (1) {
    static struct option long_options[] = {
      {"cycle-count", no_argument,       0, 'c' },
      {"help",        no_argument,       0, 'h' },
      {"max-cycles",  required_argument, 0, 'm' },
      {"seed",        required_argument, 0, 's' },
      {"rbb-port",    required_argument, 0, 'r' },
      {"verbose",     no_argument,       0, 'V' },
#if VM_TRACE
      {"vcd",         required_argument, 0, 'v' },
      {"dump-start",  required_argument, 0, 'x' },
      {"fst",         required_argument, 0, 'f' },
#endif
#if DII
      {"socket-name",         required_argument, 0, 'q' },
      {"socket-default-port",  required_argument, 0, 'w' },
#endif
      HTIF_LONG_OPTIONS
    };
    int option_index = 0;
#if VM_TRACE
    int c = getopt_long(argc, argv, "-chpm:s:r:v:f:Vx:", long_options, &option_index);
#else
    int c = getopt_long(argc, argv, "-chpm:s:r:V", long_options, &option_index);
#endif
    if (c == -1) break;
 retry:
    switch (c) {
      // Process long and short EMULATOR options
      case '?': usage(argv[0]);             return 1;
      case 'c': print_cycles = true;        break;
      case 'h': usage(argv[0]);             return 0;
      case 'm': max_cycles = atoll(optarg); break;
      case 's': random_seed = atoi(optarg); break;
      case 'r': rbb_port = atoi(optarg);    break;
      case 'V': verbose = true;             break;
      case 'p': perf = true;                break;
#ifdef DII
      case 'q': {
        socket_name = (char*) malloc(strlen(optarg));
        strcpy(socket_name,optarg);
        break;
      }
      case 'w': socket_default_port = atoi(optarg); break;
#endif
#if VM_TRACE
      case 'v': {
        vcdfile = strcmp(optarg, "-") == 0 ? stdout : fopen(optarg, "w");
        if (!vcdfile) {
          std::cerr << "Unable to open " << optarg << " for VCD write\n";
          return 1;
        }
        break;
      }
      case 'f': {
        fst_fname = optarg;
        break;
      }
      case 'x': start = atoll(optarg);      break;
#endif
      // Process legacy '+' EMULATOR arguments by replacing them with
      // their getopt equivalents
      case 1: {
        std::string arg = optarg;
        if (arg.substr(0, 1) != "+") {
          optind--;
          goto done_processing;
        }
        if (arg == "+verbose")
          c = 'V';
        else if (arg.substr(0, 12) == "+max-cycles=") {
          c = 'm';
          optarg = optarg+12;
        }
#if VM_TRACE
        else if (arg.substr(0, 12) == "+dump-start=") {
          c = 'x';
          optarg = optarg+12;
        }
#endif
        else if (arg.substr(0, 12) == "+cycle-count")
          c = 'c';
        // If we don't find a legacy '+' EMULATOR argument, it still could be
        // a VERILOG_PLUSARG and not an error.
        else if (verilog_plusargs_legal) {
          const char ** plusarg = &verilog_plusargs[0];
          int legal_verilog_plusarg = 0;
          while (*plusarg && (legal_verilog_plusarg == 0)){
            if (arg.substr(1, strlen(*plusarg)) == *plusarg) {
              legal_verilog_plusarg = 1;
            }
            plusarg ++;
          }
          if (!legal_verilog_plusarg) {
            verilog_plusargs_legal = 0;
          } else {
            c = 'P';
          }
          goto retry;
        }
        // If we STILL don't find a legacy '+' argument, it still could be
        // an HTIF (HOST) argument and not an error. If this is the case, then
        // we're done processing EMULATOR and VERILOG arguments.
        else {
          static struct option htif_long_options [] = { HTIF_LONG_OPTIONS };
          struct option * htif_option = &htif_long_options[0];
          while (htif_option->name) {
            if (arg.substr(1, strlen(htif_option->name)) == htif_option->name) {
              optind--;
              goto done_processing;
            }
            htif_option++;
          }
          std::cerr << argv[0] << ": invalid plus-arg (Verilog or HTIF) \""
                    << arg << "\"\n";
          c = '?';
        }
        goto retry;
      }
      case 'P': break; // Nothing to do here, Verilog PlusArg
      // Realize that we've hit HTIF (HOST) arguments or error out
      default:
        if (c >= HTIF_LONG_OPTIONS_OPTIND) {
          optind--;
          goto done_processing;
        }
        c = '?';
        goto retry;
    }
  }

done_processing:
  /* if (optind == argc) {
    std::cerr << "No binary specified for emulator\n";
    usage(argv[0]);
    return 1;
  } */
  int htif_argc = 1 + argc - optind;
  htif_argv = (char **) malloc((htif_argc) * sizeof (char *));
  htif_argv[0] = argv[0];
  for (int i = 1; optind < argc;) htif_argv[i++] = argv[optind++];
  std::cout << "start" << std::endl;

  const char *vcd_file = NULL;
  Verilated::commandArgs(argc, argv);

  jtag = new remote_bitbang_t(rbb_port);
  dtm = new preload_aware_dtm_t(htif_argc, htif_argv);
  signal(SIGTERM, handle_sigterm);

  Variane_testharness_dii* top(new Variane_testharness_dii);
  //read_elf(htif_argv[1]);

#if VM_TRACE
  Verilated::traceEverOn(true); // Verilator must compute traced signals
#if VM_TRACE_FST
  std::unique_ptr<VerilatedFstC> tfp(new VerilatedFstC());
  if (fst_fname) {
    std::cerr << "Starting FST waveform dump into file '" << fst_fname << "'...\n";
    top->trace(tfp.get(), 99);  // Trace 99 levels of hierarchy
    tfp->open(fst_fname);
  }
  else
    std::cerr << "No explicit FST file name supplied, using RTL defaults.\n";
#else
  std::unique_ptr<VerilatedVcdFILE> vcdfd(new VerilatedVcdFILE(vcdfile));
  std::unique_ptr<VerilatedVcdC> tfp(new VerilatedVcdC(vcdfd.get()));
  if (vcdfile) {
    std::cerr << "Starting VCD waveform dump ...\n";
    top->trace(tfp.get(), 99);  // Trace 99 levels of hierarchy
    tfp->open("");
  }
  else
    std::cerr << "No explicit VCD file name supplied, using RTL defaults.\n";
#endif
#endif

  for (int i = 0; i < 10; i++) {
    top->rst_ni = 0;
    top->clk_i = 0;
    top->rtc_i = 0;
    top->eval();
#if VM_TRACE
    if (vcdfile || fst_fname)
      tfp->dump(static_cast<vluint64_t>(main_time * 2));
#endif
    top->clk_i = 1;
    top->eval();
#if VM_TRACE
    if (vcdfile || fst_fname)
      tfp->dump(static_cast<vluint64_t>(main_time * 2 + 1));
#endif
    main_time++;
  }
  top->rst_ni = 1;
  // Preload memory.
#if (VERILATOR_VERSION_INTEGER >= 5000000)
  // Verilator v5: Use rootp pointer and .data() accessor.
#define MEM top->rootp->ariane_testharness_dii__DOT__i_sram__DOT__gen_cut__BRA__0__KET____DOT__i_tc_sram_wrapper__DOT__i_tc_sram__DOT__sram.m_storage
#else
  // Verilator v4
#define MEM top->ariane_testharness_dii__DOT__i_sram__DOT__gen_cut__BRA__0__KET____DOT__i_tc_sram_wrapper__DOT__i_tc_sram__DOT__sram
#endif
  long long addr;
  long long len;

#ifdef DII
  size_t mem_size = 0x900000;
#else
  size_t mem_size = 0xFFFFFF;
  while(get_section(&addr, &len))
  {
    if (addr == 0x80000000)
        read_section_void(addr, (void *) MEM , mem_size);
  }
#endif
#ifdef DII
  unsigned long long socket = serv_socket_create(socket_name, socket_default_port);
  serv_socket_init(socket);
  unsigned int received = 0;
  unsigned int insn_count = 0;
  unsigned int traces_count = 0;
  unsigned int num_insn = 0;
  // instruction 
  bool busy = false;
  bool inflight = false;
  bool eof_trace = false;
  RVFI_DII_Instruction_Packet next_instruction;
  char recbuf[sizeof(RVFI_DII_Instruction_Packet) + 1] = {0};
  std::vector<RVFI_DII_Instruction_Packet> instructions;
  std::vector<RVFI_DII_Execution_Packet> returntrace;
#endif
#if !defined(DROMAJO) || !defined(DII)
  while (!dtm->done() && !jtag->done() && !(top->exit_o & 0x1)) {
#else
  // the simulation gets killed by dromajo
  while (true) {
#endif

#ifdef DII
    // Routine to fetch a batch of intructions from the Vengine
    if (num_insn == 0) {
      fetchInstructions(instructions, received, socket);
      busy = true;
      num_insn = instructions.size();
    }
    
    while (busy) {
        if (readTrace(returntrace, top)){
          traces_count++;
        }
      // Routine to inject instructions into the core via RVFIDII interface
      if (!instructions.empty() /* && !inflight */){
        if ((traces_count != num_insn-1) && (top->rvfi_trap_o || (top->rvfi_valid_o && (top->rvfi_insn_o & 0x7F) == 0xF))) {
          insn_count = traces_count;
        }
        next_instruction = instructions.at(insn_count);
        if (next_instruction.dii_cmd && insn_count == traces_count) {
          top->dii_valid_i = 1;
        } else {
          top->dii_valid_i = 0;
        }
        top->dii_insn_i = next_instruction.dii_insn;
        if (top->dii_ready_o && next_instruction.dii_cmd && insn_count == traces_count){
          inflight = true;
          insn_count++;
        } else if (!next_instruction.dii_cmd && traces_count == num_insn-1) {
          insn_count++;
          eof_trace = true;
          top->dii_valid_i = 0;
          inflight = false;
        }
      }
#endif
    top->clk_i = 0;
    top->eval();
#if VM_TRACE
    if (vcdfile || fst_fname)
      tfp->dump(static_cast<vluint64_t>(main_time * 2));
#endif

    top->clk_i = 1;
    top->eval();
#if VM_TRACE
    if (vcdfile || fst_fname)
      tfp->dump(static_cast<vluint64_t>(main_time * 2 + 1));
#endif
    // toggle RTC
    if (main_time % 2 == 0) {
      top->rtc_i ^= 1;
    }
    main_time++;

    // Reset Routine 
      if (eof_trace){
        for (int i = 0; i < 10; i++) {
          top->rst_ni = 0;
          top->clk_i = 0;
          top->rtc_i = 0;
          top->eval();
        #if VM_TRACE
          if (vcdfile || fst_fname)
            tfp->dump(static_cast<vluint64_t>(main_time * 2));
        #endif
          top->clk_i = 1;
          top->eval();
        #if VM_TRACE
          if (vcdfile || fst_fname)
            tfp->dump(static_cast<vluint64_t>(main_time * 2 + 1));
          #endif
          main_time++;
        }
        top->rst_ni = 1;
        eof_trace = false;
        inflight = false;
        busy = false;
        traces_count = 0;
        insn_count = 0;
        num_insn = 0;
        // Clear memory
        for (int i = 0; i < (sizeof(MEM)/sizeof(MEM[0])); i++) {
            MEM[i] = 0;
        }
        RVFI_DII_Execution_Packet rstpack = {
          .rvfi_halt = 1
        };
        returntrace.push_back(rstpack);
        instructions.clear();
      }
    }
    // Routine to return trace to Vengine
    while (!returntrace.empty()) {
      returnTrace(returntrace, socket);
    }
  }

#if VM_TRACE
  if (tfp)
    tfp->close();
  if (vcdfile)
    fclose(vcdfile);
#endif

  /* if (dtm->exit_code()) {
    fprintf(stderr, "%s *** FAILED *** (tohost = %d) after %ld cycles\n", htif_argv[1], dtm->exit_code(), main_time);
    ret = dtm->exit_code();
  } else if (jtag->exit_code()) {
    fprintf(stderr, "%s *** FAILED *** (tohost = %d, seed %d) after %ld cycles\n", htif_argv[1], jtag->exit_code(), random_seed, main_time);
    ret = jtag->exit_code();
  } else if (top->exit_o & 0xFFFFFFFE) {
    int exitcode = ((unsigned int) top->exit_o) >> 1;
    fprintf(stderr, "%s *** FAILED *** (tohost = %d) after %ld cycles\n", htif_argv[1], exitcode, main_time);
    ret = exitcode;
  } else {
    fprintf(stderr, "%s *** SUCCESS *** (tohost = 0) after %ld cycles\n", htif_argv[1], main_time);
  } */

  if (dtm) delete dtm;
  if (jtag) delete jtag;

  std::clock_t c_end = std::clock();
  auto t_end = std::chrono::high_resolution_clock::now();

  if (perf) {
    std::cout << std::fixed << std::setprecision(2) << "CPU time used: "
              << 1000.0 * (c_end-c_start) / CLOCKS_PER_SEC << " ms\n"
              << "Wall clock time passed: "
              << std::chrono::duration<double, std::milli>(t_end-t_start).count()
              << " ms\n";
  }

  return ret;
}

// Routine to fetch intructions from the Vengine
void fetchInstructions(std::vector<RVFI_DII_Instruction_Packet> &instructions, unsigned int &cnt_rec, unsigned long long socket){
  RVFI_DII_Instruction_Packet *ins_packet;
  bool eof_rec = false;
  char recbuf[sizeof(RVFI_DII_Instruction_Packet) + 1] = {0};
  // try to receive a packet
  do {
    serv_socket_getN((unsigned int *) recbuf, socket, sizeof(RVFI_DII_Instruction_Packet));
    // the last byte received will be 0 if our attempt to receive a packet was successful
    if (recbuf[sizeof(RVFI_DII_Instruction_Packet)] == 0) {
      ins_packet = (RVFI_DII_Instruction_Packet *) recbuf;
      instructions.push_back(*ins_packet);
      PrintInstTrace(ins_packet);
      cnt_rec++;
      if (ins_packet->dii_cmd == 0) eof_rec = true;
    } else {
      // sleep for 1ms before retrying
      usleep(1000);
    }
  } while(!eof_rec);
}

RVFI_DII_Execution_Packet readRVFI(Variane_testharness_dii *top) {
    RVFI_DII_Execution_Packet execpacket = {
         .rvfi_order = top->rvfi_order_o,
         .rvfi_pc_rdata = top->rvfi_pc_rdata_o ,
         .rvfi_pc_wdata = top->rvfi_pc_wdata_o ,
         .rvfi_insn = top->rvfi_insn_o ,
         .rvfi_rs1_data = top->rvfi_rs1_rdata_o ,
         .rvfi_rs2_data = top->rvfi_rs2_rdata_o ,
         .rvfi_rd_wdata = top->rvfi_trap_o ? 0 : top->rvfi_rd_wdata_o ,
         .rvfi_mem_addr = top->rvfi_mem_addr_o ,
         .rvfi_mem_rdata = top->rvfi_trap_o ? 0 : top->rvfi_mem_rdata_o,
         .rvfi_mem_wdata = top->rvfi_trap_o ? 0 : top->rvfi_mem_wdata_o,
         .rvfi_mem_rmask = top->rvfi_trap_o ? 0 :top->rvfi_mem_rmask_o,
         .rvfi_mem_wmask = top->rvfi_trap_o ? 0 : top->rvfi_mem_wmask_o,
         .rvfi_rs1_addr = top->rvfi_trap_o ? 0 : top->rvfi_rs1_addr_o,
         .rvfi_rs2_addr = top->rvfi_rs2_addr_o,
         .rvfi_rd_addr = top->rvfi_trap_o ? 0 : top->rvfi_rd_addr_o,
         .rvfi_trap = top->rvfi_trap_o,
         .rvfi_halt = 0,
         .rvfi_intr = top->rvfi_intr_o
     };
    return execpacket;
}

void returnTrace(std::vector<RVFI_DII_Execution_Packet> &returntrace, unsigned long long socket) {
  const int BULK_SEND = 50;
  if (returntrace.size() > 0) {
    int tosend = 1;
    for (int i = 0; i < returntrace.size(); i+=tosend) {
      tosend = 1;
      RVFI_DII_Execution_Packet sendarr[BULK_SEND];
      sendarr[0] = returntrace.front();
      // bulk send if possible
      if (returntrace.size() - i > BULK_SEND) {
          tosend = BULK_SEND;
          for (int j = 0; j < tosend; j++) {
            RVFI_DII_Execution_Packet execpacket = returntrace.front();
            sendarr[j] = returntrace.front();
            returntrace.erase(returntrace.begin());
          }
      } else {
        returntrace.erase(returntrace.begin());
      }
      for (int i = 0; i < tosend; i++) {
        PrintExecTrace(&sendarr[i]);
      }
      // loop to make sure that the packet has been properly sent
      while(!serv_socket_putN(socket, sizeof(RVFI_DII_Execution_Packet) * tosend, (unsigned int *) sendarr));
    }
  }
}

bool readTrace(std::vector<RVFI_DII_Execution_Packet> &returntrace, Variane_testharness_dii *top) {
  // read rvfi data and add packet to list of packets to send
  // the condition to read data here is that there is an rvfi valid signal
  // this deals with counting instructions that the core has finished executing
  if (top->rvfi_valid_o || top->rvfi_trap_o) {
    RVFI_DII_Execution_Packet execpacket = readRVFI(top);
    returntrace.push_back(execpacket);
    return true;
  }
  return false;
}

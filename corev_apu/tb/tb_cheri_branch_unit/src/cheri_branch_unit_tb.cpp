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

#include "Vcheri_branch_unit_testharness.h"
#include "Vcheri_branch_unit_testharness_cva6_cheri_pkg.h"
#include "Vcheri_branch_unit_testharness_ariane_pkg.h"
#include "verilated.h"
#include "verilated_vcd_c.h"

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <getopt.h>
#include <chrono>
#include <ctime>
#include <signal.h>
#include <unistd.h>
#include <gtest/gtest.h>

#define MAX_SIM_TIME 20
static vluint64_t main_time = 0;
static std::string dumpfile = "dump.vcd";

typedef struct {
  Vcheri_branch_unit_testharness_cva6_cheri_pkg::cap_fmt_t int_e;
  char ct;
  char cb;
  unsigned int exp;
  unsigned int top_bits;
  unsigned int bot_bits;
} cap_enc_bounds_t;

typedef struct {
  char ct;
  char cb;
} cap_correc_t;

typedef struct {
    unsigned char tag;
    unsigned char ct;
    unsigned char cb;
    unsigned int uperms;
    unsigned int hperms;
    unsigned char cap_mode;
    unsigned int otype;
    Vcheri_branch_unit_testharness_cva6_cheri_pkg::cap_fmt_t int_e;
    unsigned int exp;
    unsigned int top_bits;
    unsigned int bot_bits;
    unsigned int addr;
} cap_reg_t;

static const int UNSEALED_CAP     = -1;
static const int SENTRY_CAP       = -2;
static const int MEM_TYPE_TOK_CAP = -3;
static const int IND_ENT_CAP      = -4;
static const int SEALED_CAP       = -17;
static const int OTYPE_MAX        = -5;

static const int PERMIT_SET_CID         = 11;
static const int PERMIT_SYS_REGS        = 10;
static const int PERMIT_UNSEAL          = 9;
static const int PERMIT_CINVOKE         = 8;
static const int PERMIT_SEAL            = 7;
static const int PERMIT_STORE_LOCAL_CAP = 6;
static const int PERMIT_STORE_CAP       = 5;
static const int PERMIT_LOAD_CAP        = 4;
static const int PERMIT_STORE           = 3;
static const int PERMIT_LOAD            = 2;
static const int PERMIT_EXECUTE         = 1;
static const int GLOBAL                 = 0;


static const int CAP_LENGTH_VIOLATION            = 1;
static const int CAP_TAG_VIOLATION               = 2;
static const int CAP_SEAL_VIOLATION              = 3;
static const int CAP_TYPE_VIOLATION              = 4;
static const int CAP_USER_DEF_PERM_VIOLATION     = 8;
static const int CAP_REPRE_VIOLATION             = 10;
static const int CAP_UNLIGNED_BASE               = 11;
static const int CAP_GLOBAL_VIOLATION            = 16;
static const int CAP_PERM_EXEC_VIOLATION         = 17;
static const int CAP_PERM_LD_VIOLATION           = 18;
static const int CAP_PERM_ST_VIOLATION           = 19;
static const int CAP_PERM_LD_CAP_VIOLATION       = 20;
static const int CAP_PERM_ST_CAP_VIOLATION       = 21;
static const int CAP_PERM_ST_CAP_LOCAL_VIOLATION = 22;
static const int CAP_PERM_SEAL                   = 23;
static const int CAP_PERM_ACCESS_SYS_REGS        = 24;
static const int CAP_PERM_CINVOKE                = 25;
static const int CAP_PERM_ACCESS_CINVOKE_IDC     = 26;
static const int CAP_PERM_UNSEAL                 = 27;
static const int CAP_PERM_SET_CID                = 28;

static const int CAP_UPERMS_SHIFT       = 15;

class CCheri_branch_unit_tb: public ::testing::Test{
    protected:
    Vcheri_branch_unit_testharness * top;
    VerilatedVcdC * tfp;

    void SetUp()
    {
      main_time = 0;
      top = new(Vcheri_branch_unit_testharness);
      #if VM_TRACE
      // Enable Trace
      Verilated::traceEverOn(true); // Verilator must compute traced signals
      tfp = new VerilatedVcdC;
      top->trace(tfp, 99);  // Trace 99 levels of hierarchy
      std::string test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
      dumpfile = "logs/" + test_name + "_dump.vcd";
      std::cout << dumpfile << std::endl;
      tfp->open(dumpfile.c_str());
      #endif
      reset();
    }

    void TearDown() 
    {
      delete top;
      #if VM_TRACE
        tfp->close();
        delete tfp;
      #endif
    }

    public:
    void reset(){
      for (int i = 0; i < 10; i++) {
        top->rst_ni = 0;
        top->clk_i = 0;
        top->eval();
      #if VM_TRACE
        tfp->dump(static_cast<vluint64_t>(main_time * 2));
      #endif
        top->clk_i = 1;
        top->eval();
      #if VM_TRACE
        tfp->dump(static_cast<vluint64_t>(main_time * 2 + 1));
      #endif
        main_time++;
      }
      top->rst_ni = 1;
    }

    /**
     * @brief Function to tick the DUT.
     * @param N number of clock ticks to increment.
     * @returns void.
     */
    void tick(int N){
      for (int i = 0; i < N; i++) {
        top->clk_i = 1;
        top->eval();
      #if VM_TRACE
         tfp->dump(static_cast<vluint64_t>(main_time * 2));
      #endif
        top->clk_i = 0;
        top->eval();
      #if VM_TRACE
        tfp->dump(static_cast<vluint64_t>(main_time * 2 + 1));
      #endif
        main_time++;
      }
    }

    /**
     * @brief Function to count the number of zeros in the MSBs from [64:13] of val.
     * @details Starts counting from 64 to 13. Stops when finds a 1.
     * @param val number of clock ticks to increment.
     * @returns number of counted zeros from [64:13].
     */
    int count_leading_zeros(unsigned long long int val){
      int cnt_zeros = 0;
      for (int i = 64; i >= 13; i--)
      {
        if (((val >> i) & 1) == 0)
          cnt_zeros++;
        else 
          break;
      }
      return cnt_zeros;
    }

    /**
     * @brief Function to compute the corrections values according to Fig 3.1 of CHERI Concentrate Compression 
     * @param base capability base value.
     * @param top capability top value.
     * @param addr capability addr value.
     * @param exp capability exponent value (E) value.
     * @returns number of counted zeros from [64:13].
     */
    cap_correc_t get_corrections(unsigned int base, unsigned long long int top, unsigned int addr, int exp) {
      int base3 = (base >> 11) & 7;
      int top3 = (base >> 11) & 7;
      int addr3 = (addr >> (exp + 11))& 7;
      int r = base3 - 1;
      bool cmp_r_base3 = base3 < r;
      bool cmp_r_top3  = top3 < r;
      bool cmp_r_addr3 = addr3 < r;
      cap_correc_t corrs = {0,0};

      if ((cmp_r_base3 && cmp_r_addr3) || (!cmp_r_base3 && !cmp_r_addr3)) {
        corrs.cb = 0;
      } else if (!cmp_r_base3 && cmp_r_addr3) {
        corrs.cb = -1;
      }
      else {
        corrs.cb = 1;
      }

      if ((cmp_r_top3 && cmp_r_addr3) || (!cmp_r_top3 && !cmp_r_addr3)) {
        corrs.ct = 0;
      } else if (!cmp_r_top3 && cmp_r_addr3) {
        corrs.ct = -1;
      }
      else {
        corrs.ct = 1;
      }

      return corrs;
    }

     /**
     * @brief Function to encode values according to CHERI Concentrate Compression - Concentrate Encoding
     * @param base capability base value.
     * @param length capability length value.
     * @param addr capability addr value.
     * @returns the encoded bounds (top_bits, base_bits, exp, cb and ct).
     */
    cap_enc_bounds_t encode_bounds (unsigned int bot, unsigned long long int length, int addr) {
        int exp = 52 - count_leading_zeros(length);
        unsigned long long int top = bot + length;
        cap_enc_bounds_t ret_bounds;
        cap_correc_t corr;

        if ((exp == 0) && (((length >> 12) & 1) == 0)) {
          ret_bounds.int_e = Vcheri_branch_unit_testharness_cva6_cheri_pkg::EXP0;
          ret_bounds.bot_bits = bot & 0x3FFF;
          ret_bounds.top_bits = top & 0x3FFF;
          ret_bounds.exp = 0;
        } else {
          ret_bounds.int_e = Vcheri_branch_unit_testharness_cva6_cheri_pkg::EMBEDDED_EXP;
          ret_bounds.bot_bits = (((bot >> (exp+3)) & 0x3FFF) << 3) & 0x3FFF; 
          ret_bounds.top_bits = (((top  >> (exp+3)) & 0x3FFF) << 3)& 0x3FFF;;
          ret_bounds.exp = exp;
        }
        corr = get_corrections(ret_bounds.bot_bits, ret_bounds.top_bits, addr, exp);
        ret_bounds.cb = corr.cb & 3;
        ret_bounds.ct = corr.ct & 3;
        return ret_bounds;
    }
};

static void usage(const char * program_name) {
  fputs("\
    Run CHERI ALU Testbench.\n\
  ", stdout);
  fputs("\
  -v,                      Write vcd trace to FILE\n\
  ", stdout);
}


// Test CJALR
TEST_F(CCheri_branch_unit_tb, CJALR) {
    top->fu_data_operator_i  = Vcheri_branch_unit_testharness_ariane_pkg::CJALR;
    top->fu_data_fu_i        = Vcheri_branch_unit_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 0;
    top->set_pcc_full_cap_i  = 0;
    top->fu_valid_i          = 1;
    top->branch_valid_i      = 1;
    top->branch_comp_res_i   = 1;
    top->is_compressed_instr_i = 0;
    top->pcc_cap_mode_i      = 1;
    top->op_a_cap_mode_i      = 1;

    /// Set operand a capability
    uint64_t addr_a = 0x22000;
    uint64_t length_a = 0xA000;
    uint64_t base_a = 0x20000;
    uint64_t top_addr_a = base_a + length_a;
    cap_enc_bounds_t bounds_a = encode_bounds(base_a,length_a,addr_a);

    top->op_a_addr_i = addr_a;
    top->op_a_int_e_i = bounds_a.int_e;
    top->op_a_bounds_exp_i = bounds_a.exp;
    top->op_a_bounds_base_bits_i = bounds_a.bot_bits;
    top->op_a_bounds_top_bits_i = bounds_a.top_bits;
    top->op_a_otype_i = SENTRY_CAP & 0x3FFFF;
    top->op_a_tag_i = 1;
    top->op_a_uperms_i = 0xF;
    top->op_a_hperms_i = (1 << PERMIT_EXECUTE);

    /// Set PCC capability
    uint64_t pc = 0x20000;
    uint64_t length = 0xA000;
    uint64_t base = 0x1E000;
    uint64_t top_addr = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base,length,pc);

    top->pcc_addr_i = pc;
    top->pcc_int_e_i = bounds.int_e;
    top->pcc_bounds_exp_i = bounds.exp;
    top->pcc_bounds_base_bits_i = bounds.bot_bits;
    top->pcc_bounds_top_bits_i = bounds.top_bits;
    top->pcc_otype_i = UNSEALED_CAP & 0x3FFFF;
    top->pcc_tag_i = 1;
    top->pcc_uperms_i = 0xF;
    top->pcc_hperms_i = (1 << PERMIT_EXECUTE);

    /// Check CD register is equal to the next instruction of PCC and sealed as sentry
    /// Check if the next pcc is equal to PC + imm
    uint64_t cd_addr = pc + 4;
    int imm          = 0x2000;
    int next_pc = addr_a + imm;

    top->fu_data_imm_i = imm;
    tick(1);
    ASSERT_EQ(top->branch_result_addr_o, cd_addr);
    ASSERT_EQ(top->branch_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->branch_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->branch_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->branch_result_bounds_top_bits_o, bounds.top_bits);
    ASSERT_EQ(top->branch_result_otype_o, SENTRY_CAP & 0x3FFFF);
    ASSERT_EQ(top->branch_result_tag_o, 1);
    ASSERT_EQ(top->branch_result_uperms_o, 0xF);
    ASSERT_EQ(top->branch_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->branch_result_cap_mode_o, 1);
    ASSERT_EQ(top->branch_ex_valid_o,0);

    // Assert PC Gen
    ASSERT_EQ(top->resolved_branch_target_address_addr_o, next_pc);
    ASSERT_EQ(top->resolved_branch_target_address_int_e_o, bounds_a.int_e);
    ASSERT_EQ(top->resolved_branch_target_address_exp_o, bounds_a.exp);
    ASSERT_EQ(top->resolved_branch_target_address_base_o, base_a);
    ASSERT_EQ(top->resolved_branch_target_address_top_o, top_addr_a);
    ASSERT_EQ(top->resolved_branch_target_address_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->resolved_branch_target_address_tag_o, 1);
    ASSERT_EQ(top->resolved_branch_target_address_uperms_o, 0xF);
    ASSERT_EQ(top->resolved_branch_target_address_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->resolved_branch_target_address_cap_mode_o, 1);

    // check of exception when operand a tag is cleared
    top->op_a_tag_i = 0;
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_tval_o,ex);
    top->op_a_tag_i = 1;

   /*  // Check if exception is raised when PCC.address + imm < PCC.base
    imm = - (pc - base) - 0x2000;
    next_pc = pc + imm;
    top->fu_data_imm_i = imm;
    uint64_t ex = (1 << 10) + CAP_LENGTH_VIOLATION;
    tick(1);
    ASSERT_EQ(top->branch_result_addr_o, cd_addr);
    ASSERT_EQ(top->branch_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->branch_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->branch_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->branch_result_bounds_top_bits_o, bounds.top_bits);
    ASSERT_EQ(top->branch_result_otype_o, SENTRY_CAP & 0x3FFFF);
    ASSERT_EQ(top->branch_result_tag_o, 1);
    ASSERT_EQ(top->branch_result_uperms_o, 0xF);
    ASSERT_EQ(top->branch_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->branch_result_cap_mode_o, 1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_tval_o,ex);

    // Assert PC Gen
    ASSERT_EQ(top->resolved_branch_target_address_addr_o, next_pc);
    ASSERT_EQ(top->resolved_branch_target_address_int_e_o, bounds.int_e);
    ASSERT_EQ(top->resolved_branch_target_address_exp_o, bounds.exp);
    ASSERT_EQ(top->resolved_branch_target_address_base_o, base);
    ASSERT_EQ(top->resolved_branch_target_address_top_o, top_addr);
    ASSERT_EQ(top->resolved_branch_target_address_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->resolved_branch_target_address_tag_o, 1);
    ASSERT_EQ(top->resolved_branch_target_address_uperms_o, 0xF);
    ASSERT_EQ(top->resolved_branch_target_address_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->resolved_branch_target_address_cap_mode_o, 1);

    // Check if exception is raised when PCC.address + imm + 4 > PCC.TOP
    imm = (top_addr - pc) + 2;
    next_pc = pc + imm;
    top->fu_data_imm_i = imm;
    ex = (1 << 10) + CAP_LENGTH_VIOLATION;
    tick(1);
    ASSERT_EQ(top->branch_result_addr_o, cd_addr);
    ASSERT_EQ(top->branch_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->branch_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->branch_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->branch_result_bounds_top_bits_o, bounds.top_bits);
    ASSERT_EQ(top->branch_result_otype_o, SENTRY_CAP & 0x3FFFF);
    ASSERT_EQ(top->branch_result_tag_o, 1);
    ASSERT_EQ(top->branch_result_uperms_o, 0xF);
    ASSERT_EQ(top->branch_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->branch_result_cap_mode_o, 1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_tval_o,ex);

    // Assert PC Gen
    ASSERT_EQ(top->resolved_branch_target_address_addr_o, next_pc);
    ASSERT_EQ(top->resolved_branch_target_address_int_e_o, bounds.int_e);
    ASSERT_EQ(top->resolved_branch_target_address_exp_o, bounds.exp);
    ASSERT_EQ(top->resolved_branch_target_address_base_o, base);
    ASSERT_EQ(top->resolved_branch_target_address_top_o, top_addr);
    ASSERT_EQ(top->resolved_branch_target_address_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->resolved_branch_target_address_tag_o, 1);
    ASSERT_EQ(top->resolved_branch_target_address_uperms_o, 0xF);
    ASSERT_EQ(top->resolved_branch_target_address_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->resolved_branch_target_address_cap_mode_o, 1); */
}

// Test CJAL
TEST_F(CCheri_branch_unit_tb, CJAL) {
    top->fu_data_operator_i  = Vcheri_branch_unit_testharness_ariane_pkg::CJAL;
    top->fu_data_fu_i        = Vcheri_branch_unit_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 0;
    top->set_pcc_full_cap_i  = 0;
    top->fu_valid_i          = 1;
    top->branch_valid_i      = 1;
    top->branch_comp_res_i   = 1;
    top->is_compressed_instr_i = 0;
    top->pcc_cap_mode_i      = 1;

    /// Set PCC capability
    uint64_t pc = 0x20000;
    uint64_t length = 0xA000;
    uint64_t base = 0x1E000;
    uint64_t top_addr = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base,length,pc);

    top->pcc_addr_i = pc;
    top->pcc_int_e_i = bounds.int_e;
    top->pcc_bounds_exp_i = bounds.exp;
    top->pcc_bounds_base_bits_i = bounds.bot_bits;
    top->pcc_bounds_top_bits_i = bounds.top_bits;
    top->pcc_otype_i = UNSEALED_CAP & 0x3FFFF;
    top->pcc_tag_i = 1;
    top->pcc_uperms_i = 0xF;
    top->pcc_hperms_i = (1 << PERMIT_EXECUTE);

    /// Check CD register is equal to the next instruction of PCC and sealed as sentry
    /// Check if the next pcc is equal to PC + imm
    uint64_t cd_addr = pc + 4;
    int imm          = 0x2000;
    int next_pc = pc + imm;

    top->fu_data_imm_i = imm;
    tick(1);
    ASSERT_EQ(top->branch_result_addr_o, cd_addr);
    ASSERT_EQ(top->branch_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->branch_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->branch_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->branch_result_bounds_top_bits_o, bounds.top_bits);
    ASSERT_EQ(top->branch_result_otype_o, SENTRY_CAP & 0x3FFFF);
    ASSERT_EQ(top->branch_result_tag_o, 1);
    ASSERT_EQ(top->branch_result_uperms_o, 0xF);
    ASSERT_EQ(top->branch_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->branch_result_cap_mode_o, 1);
    ASSERT_EQ(top->branch_ex_valid_o,0);

    // Assert PC Gen
    ASSERT_EQ(top->resolved_branch_target_address_addr_o, next_pc);
    ASSERT_EQ(top->resolved_branch_target_address_int_e_o, bounds.int_e);
    ASSERT_EQ(top->resolved_branch_target_address_exp_o, bounds.exp);
    ASSERT_EQ(top->resolved_branch_target_address_base_o, base);
    ASSERT_EQ(top->resolved_branch_target_address_top_o, top_addr);
    ASSERT_EQ(top->resolved_branch_target_address_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->resolved_branch_target_address_tag_o, 1);
    ASSERT_EQ(top->resolved_branch_target_address_uperms_o, 0xF);
    ASSERT_EQ(top->resolved_branch_target_address_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->resolved_branch_target_address_cap_mode_o, 1);

    // Check if exception is raised when PCC.address + imm < PCC.base
    imm = - (pc - base) - 0x2000;
    next_pc = pc + imm;
    top->fu_data_imm_i = imm;
    uint64_t ex = (1 << 10) + CAP_LENGTH_VIOLATION;
    tick(1);
    ASSERT_EQ(top->branch_result_addr_o, cd_addr);
    ASSERT_EQ(top->branch_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->branch_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->branch_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->branch_result_bounds_top_bits_o, bounds.top_bits);
    ASSERT_EQ(top->branch_result_otype_o, SENTRY_CAP & 0x3FFFF);
    ASSERT_EQ(top->branch_result_tag_o, 1);
    ASSERT_EQ(top->branch_result_uperms_o, 0xF);
    ASSERT_EQ(top->branch_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->branch_result_cap_mode_o, 1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_tval_o,ex);

    // Assert PC Gen
    ASSERT_EQ(top->resolved_branch_target_address_addr_o, next_pc);
    ASSERT_EQ(top->resolved_branch_target_address_int_e_o, bounds.int_e);
    ASSERT_EQ(top->resolved_branch_target_address_exp_o, bounds.exp);
    ASSERT_EQ(top->resolved_branch_target_address_base_o, base);
    ASSERT_EQ(top->resolved_branch_target_address_top_o, top_addr);
    ASSERT_EQ(top->resolved_branch_target_address_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->resolved_branch_target_address_tag_o, 1);
    ASSERT_EQ(top->resolved_branch_target_address_uperms_o, 0xF);
    ASSERT_EQ(top->resolved_branch_target_address_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->resolved_branch_target_address_cap_mode_o, 1);

    // Check if exception is raised when PCC.address + imm + 4 > PCC.TOP
    imm = (top_addr - pc) + 2;
    next_pc = pc + imm;
    top->fu_data_imm_i = imm;
    ex = (1 << 10) + CAP_LENGTH_VIOLATION;
    tick(1);
    ASSERT_EQ(top->branch_result_addr_o, cd_addr);
    ASSERT_EQ(top->branch_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->branch_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->branch_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->branch_result_bounds_top_bits_o, bounds.top_bits);
    ASSERT_EQ(top->branch_result_otype_o, SENTRY_CAP & 0x3FFFF);
    ASSERT_EQ(top->branch_result_tag_o, 1);
    ASSERT_EQ(top->branch_result_uperms_o, 0xF);
    ASSERT_EQ(top->branch_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->branch_result_cap_mode_o, 1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_valid_o,1);
    ASSERT_EQ(top->branch_ex_tval_o,ex);

    // Assert PC Gen
    ASSERT_EQ(top->resolved_branch_target_address_addr_o, next_pc);
    ASSERT_EQ(top->resolved_branch_target_address_int_e_o, bounds.int_e);
    ASSERT_EQ(top->resolved_branch_target_address_exp_o, bounds.exp);
    ASSERT_EQ(top->resolved_branch_target_address_base_o, base);
    ASSERT_EQ(top->resolved_branch_target_address_top_o, top_addr);
    ASSERT_EQ(top->resolved_branch_target_address_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->resolved_branch_target_address_tag_o, 1);
    ASSERT_EQ(top->resolved_branch_target_address_uperms_o, 0xF);
    ASSERT_EQ(top->resolved_branch_target_address_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->resolved_branch_target_address_cap_mode_o, 1);
}

int main(int argc, char **argv) {
  std::clock_t c_start = std::clock();
  auto t_start = std::chrono::high_resolution_clock::now();
  int option_index = 0;
  char * filename = nullptr;
#if VM_TRACE
  while((option_index = getopt(argc, argv, "hv:")) != -1)
#else
  while((option_index = getopt(argc, argv, "h")) != -1)
#endif
  { 
    switch (option_index) {
      // Process long and short EMULATOR options
      case 'h': usage(argv[0]);             return 1;
#if VM_TRACE
      case 'v': {
        dumpfile = optarg;
        std::cout << "VCD filename: " << dumpfile << std::endl;
        break;
      }
#endif
    }
  }
  ::testing::InitGoogleTest(&argc, argv);
  auto ret = RUN_ALL_TESTS();
  std::clock_t c_end = std::clock();
  auto t_end = std::chrono::high_resolution_clock::now();
  std::cout << std::fixed << std::setprecision(2) << "CPU time used: "
              << 1000.0 * (c_end-c_start) / CLOCKS_PER_SEC << " ms\n"
              << "Wall clock time passed: "
              << std::chrono::duration<double, std::milli>(t_end-t_start).count()
              << " ms\n";
  return ret;
}

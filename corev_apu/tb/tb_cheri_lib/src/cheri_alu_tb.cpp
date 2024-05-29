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

#include "Vcheri_alu_testharness.h"
#include "Vcheri_alu_testharness_cva6_cheri_pkg.h"
#include "Vcheri_alu_testharness_ariane_pkg.h"
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
  Vcheri_alu_testharness_cva6_cheri_pkg::cap_fmt_t int_e;
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
    Vcheri_alu_testharness_cva6_cheri_pkg::cap_fmt_t int_e;
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

class CCheri_lib_tb: public ::testing::Test{
    protected:
    Vcheri_alu_testharness * top;
    VerilatedVcdC * tfp;

    void SetUp()
    {
      main_time = 0;
      top = new(Vcheri_alu_testharness);
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
        top->v_i = 0;
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
          ret_bounds.int_e = Vcheri_alu_testharness_cva6_cheri_pkg::EXP0;
          ret_bounds.bot_bits = bot & 0x3FFF;
          ret_bounds.top_bits = top & 0x3FFF;
          ret_bounds.exp = 0;
        } else {
          ret_bounds.int_e = Vcheri_alu_testharness_cva6_cheri_pkg::EMBEDDED_EXP;
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
    Run CHERI Lib Testbench.\n\
  ", stdout);
  fputs("\
  -v,                      Write vcd trace to FILE\n\
  ", stdout);
}


// Test RND_REPRESENTABLE_LEN and MSK
TEST_F(CCheri_lib_tb, RND_REPRESENTABLE_LEN_AND_MSK) {
    unsigned long long int length = 0xA000;
    top->clu_valid_i = 1;
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CRND_REPRESENTABLE_LEN;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->op_a_addr_i = length;
    
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o,length);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CRND_REPRESENTABLE_ALIGN_MSK;
    tick(1);
    uint64_t exp = 52 - count_leading_zeros(length);
    uint64_t msk = - 1 << (exp + 3);
    ASSERT_EQ(top->clu_result_addr_o,msk);

    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CRND_REPRESENTABLE_LEN;
    length = 0xFFFE;
    top->op_a_addr_i = length;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o,((length + (1 << 6)) & ~0x3f));

    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CRND_REPRESENTABLE_ALIGN_MSK;
    exp = 52 - count_leading_zeros(length);
    msk = - 1 << (exp + 5);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, msk);
}

    unsigned long long int length = 0xA000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x1F000;
    uint64_t new_len = 0x4000;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CSET_BOUNDS_EXACT;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 0;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_addr_i = addr;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    
    top->op_a_otype_i = UNSEALED_CAP & 0x3FFFF;
    top->op_a_tag_i = 1;
    top->op_a_uperms_i = 0;
    top->op_a_hperms_i = 1 << PERMIT_EXECUTE;
    top->op_b_addr_i = new_len;

    cap_enc_bounds_t new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Test what happens when len exp bits are set
    new_len = 0x403C;
    top->op_b_addr_i = new_len;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits + 8);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Test what happens when base exp bits are set
    new_len = 0x4000;
    top->op_b_addr_i = new_len;
    addr = 0x1F01C;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits + 8);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Test what happens when len + base overflow in exp bits
    new_len = 0x4010;
    top->op_b_addr_i = new_len;
    addr = 0x1F01C;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits + 8);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);
    // Test length overflow
    new_len = 0x7FE0;
    top->op_b_addr_i = new_len;
    addr = 0x1F000;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp + 1);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, (addr >> (new_bounds.exp + 1)) & 0x3FF8);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, (((addr + new_len) >> (new_bounds.exp + 1)) & 0x3FF8));
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Length bigger then top
    new_len = 0xA000;
    top->op_b_addr_i = new_len;
    addr = 0x1F000;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_tag_o, 0);

    // Length less than bottom
    new_len = -0xA000;
    top->op_b_addr_i = new_len;
    addr = 0x1F000;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_tag_o, 0);
}

// Test SET_BOUNDS
TEST_F(CCheri_lib_tb, SET_BOUNDS) {
    unsigned long long int length = 0xA000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x1F000;
    uint64_t new_len = 0x4000;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CSET_BOUNDS;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 0;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_addr_i = addr;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    
    top->op_a_otype_i = UNSEALED_CAP & 0x3FFFF;
    top->op_a_tag_i = 1;
    top->op_a_uperms_i = 0;
    top->op_a_hperms_i = 1 << PERMIT_EXECUTE;
    top->op_b_addr_i = new_len;

    cap_enc_bounds_t new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Test what happens when len exp bits are set
    new_len = 0x403C;
    top->op_b_addr_i = new_len;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits + 8);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Test what happens when base exp bits are set
    new_len = 0x4000;
    top->op_b_addr_i = new_len;
    addr = 0x1F01C;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits + 8);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Test what happens when len + base overflow in exp bits
    new_len = 0x4010;
    top->op_b_addr_i = new_len;
    addr = 0x1F01C;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, new_bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, new_bounds.top_bits + 8);
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);
    // Test length overflow
    new_len = 0x7FE0;
    top->op_b_addr_i = new_len;
    addr = 0x1F000;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr);
    ASSERT_EQ(top->clu_result_int_e_o, new_bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, new_bounds.exp + 1);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, (addr >> (new_bounds.exp + 1)) & 0x3FFC);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, (((addr + new_len) >> (new_bounds.exp + 1)) & 0x3FF8));
    ASSERT_EQ(top->clu_result_cb_o, new_bounds.cb);
    ASSERT_EQ(top->clu_result_ct_o, new_bounds.ct);
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Length bigger then top
    new_len = 0xA000;
    top->op_b_addr_i = new_len;
    addr = 0x1F000;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_tag_o, 0);

    // Length less than bottom
    new_len = -0xA000;
    top->op_b_addr_i = new_len;
    addr = 0x1F000;
    top->op_a_addr_i = addr;
    new_bounds = encode_bounds(addr, new_len, addr);
    tick(1);
    ASSERT_EQ(top->clu_result_tag_o, 0);
}

// Test INC_OFFSET
TEST_F(CCheri_lib_tb, INC_OFFSET) {
    unsigned long long int length = 0x6000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x20000;
    int offset = 0x2000;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CINC_OFFSET;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 0;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_addr_i = addr;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    
    top->op_a_otype_i = UNSEALED_CAP & 0x3FFFF;
    top->op_a_tag_i = 1;
    top->op_a_uperms_i = 0;
    top->op_a_hperms_i = 1 << PERMIT_EXECUTE;
    top->op_b_addr_i = offset;

    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set addr below the base addr but still representable
    offset = -0x3000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr - 0x3000);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set offset below the representable space bottom (not representable)
    offset = -0x5000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr - 0x5000);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set offset above the top addr but still representable
    offset = 0x5000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set offset above the top addr and not representable
    offset = 0xD000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, addr + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Test SET_OFFSET
TEST_F(CCheri_lib_tb, SET_OFFSET) {
    unsigned long long int length = 0x6000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x20000;
    int offset = 0x0000;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CSET_OFFSET;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 0;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_addr_i = addr;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    
    top->op_a_otype_i = UNSEALED_CAP & 0x3FFFF;
    top->op_a_tag_i = 1;
    top->op_a_uperms_i = 0;
    top->op_a_hperms_i = 1 << PERMIT_EXECUTE;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set addr below the base addr but still representable
    offset = -0x1000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set offset below the representable space bottom (not representable)
    offset = -0x4000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set offset above the top addr but still representable
    offset = 0x8000;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 1);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);

    // Set offset above the top addr and not representable
    offset = 0x2D000 - base;
    top->op_b_addr_i = offset;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base + offset);
    ASSERT_EQ(top->clu_result_int_e_o, bounds.int_e);
    ASSERT_EQ(top->clu_result_bounds_exp_o, bounds.exp);
    ASSERT_EQ(top->clu_result_bounds_base_bits_o, bounds.bot_bits);
    ASSERT_EQ(top->clu_result_bounds_top_bits_o, bounds.top_bits);
    
   
    ASSERT_EQ(top->clu_result_otype_o, UNSEALED_CAP & 0x3FFFF);
    ASSERT_EQ(top->clu_result_tag_o, 0);
    ASSERT_EQ(top->clu_result_uperms_o, 0);
    ASSERT_EQ(top->clu_result_hperms_o, 1 << PERMIT_EXECUTE);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}


// Test GET_TAG
TEST_F(CCheri_lib_tb, GET_TAG) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_TAG;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->op_a_tag_i          = 0;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 0);
    ASSERT_EQ(top->clu_ex_valid_o,0);
    top->op_a_tag_i          = 1;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 1);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Test GET_SEALED
TEST_F(CCheri_lib_tb, GET_SEALED) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_SEALED;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->op_a_otype_i        = SENTRY_CAP & 0x3FFFF;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 1);
    ASSERT_EQ(top->clu_ex_valid_o,0);
    top->op_a_otype_i        = UNSEALED_CAP & 0x3FFFF;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 0);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Test GET_PERM
TEST_F(CCheri_lib_tb, GET_PERM) {
  uint16_t hperms = 0;
  uint8_t uperms = 0;
  top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_PERM;
  top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
  top->set_op_a_full_cap_i = 0;
  top->set_op_b_full_cap_i = 1;
  top->set_pcc_full_cap_i  = 1;
  top->op_a_hperms_i = 0;
  top->op_a_uperms_i = 0;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, 0);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set uperms all to ones
  uperms = 0xF;
  top->op_a_uperms_i = uperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, uperms << CAP_UPERMS_SHIFT);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms and uperms all to ones
  hperms = 0xFFF;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, ((uperms << CAP_UPERMS_SHIFT) | hperms));
  ASSERT_EQ(top->clu_ex_valid_o,0);
  top->op_a_uperms_i = 0;
  // Test set hperms PERMIT_SET_CID
  hperms = 1 << PERMIT_SET_CID;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_SYS_REGS
  hperms = 1 << PERMIT_SYS_REGS;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_UNSEAL
  hperms = 1 << PERMIT_UNSEAL;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_CINVOKE
  hperms = 1 << PERMIT_CINVOKE;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_SEAL
  hperms = 1 << PERMIT_SEAL;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_STORE_LOCAL_CAP
  hperms = 1 << PERMIT_STORE_LOCAL_CAP;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_STORE_CAP
  hperms = 1 << PERMIT_STORE_CAP;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_LOAD_CAP
  hperms = 1 << PERMIT_LOAD_CAP;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_STORE
  hperms = 1 << PERMIT_STORE;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_LOAD
  hperms = 1 << PERMIT_LOAD;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms PERMIT_EXECUTE
  hperms = 1 << PERMIT_EXECUTE;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test set hperms GLOBAL
  hperms = 1 << GLOBAL;
  top->op_a_hperms_i = hperms;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, hperms);
  ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Test GET_OFFSET
TEST_F(CCheri_lib_tb, GET_OFFSET) {
    unsigned long long int length = 0x6000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x20001;
    uint64_t offset = addr - base;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_OFFSET;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, offset);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}


// Test GET_TYPE for reserved type
TEST_F(CCheri_lib_tb, GET_TYPE_RESERVED_TYPE) {
  top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_TYPE;
  top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
  top->set_op_a_full_cap_i = 0;
  top->set_op_b_full_cap_i = 1;
  top->set_pcc_full_cap_i  = 1;
  // Test UNSEALED_CAP
  top->op_a_otype_i = UNSEALED_CAP & 0x3FFFF;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, UNSEALED_CAP);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test SENTRY_CAP
  top->op_a_otype_i = SENTRY_CAP & 0x3FFFF;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, SENTRY_CAP);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test MEM_TYPE_TOK_CAP
  top->op_a_otype_i = MEM_TYPE_TOK_CAP & 0x3FFFF;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, MEM_TYPE_TOK_CAP);
  ASSERT_EQ(top->clu_ex_valid_o,0);
  // Test IND_ENT_CAP
  top->op_a_otype_i = IND_ENT_CAP & 0x3FFFF;
  tick(1);
  ASSERT_EQ(top->clu_result_addr_o, IND_ENT_CAP);
  ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_LEN for Lengths higher than 12-bits (E=0)
TEST_F(CCheri_lib_tb, GET_LEN_LOW_12_BITS) {
    unsigned long long int length = 0x200;
    uint64_t base = 0x80000000;
    uint64_t addr  = 0x80000100;
    uint64_t cap_top = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_LEN;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, length);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_LEN for Lengths higher than 12-bits (E=52-count_msb_bits(length))
TEST_F(CCheri_lib_tb, GET_LEN_HIGH_12_BITS) {
    unsigned long long int length = 0x6000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x20000;
    uint64_t cap_top = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_LEN;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, length);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_LEN Corner Case
TEST_F(CCheri_lib_tb, GET_LEN_CORNER_CASE) {
    unsigned long long int length = -1;
    uint64_t base = 0x80000000;
    uint64_t addr  = 0x80000100;
    uint64_t cap_top = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_LEN;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 1;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, length);
}

// Test read cap mode flag
TEST_F(CCheri_lib_tb, GET_FLAGS_RESET) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_FLAGS;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_cap_mode_i = 0;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 0);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Test read cap mode flag
TEST_F(CCheri_lib_tb, GET_FLAGS_SET) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_FLAGS;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    // Test Reset 
    top->op_a_cap_mode_i = 1;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 1);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_TOP for Lengths higher than 12-bits (E=0)
TEST_F(CCheri_lib_tb, GET_TOP_LENGTHS_LOW_12_BITS) {
    unsigned long long int length = 0x200;
    uint64_t base = 0x80000000;
    uint64_t addr  = 0x80000100;
    uint64_t cap_top = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_TOP;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, cap_top);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_TOP for Lengths higher than 12-bits (E=52-count_msb_bits(length))
TEST_F(CCheri_lib_tb, GET_TOP_LENGTHS_HIGH_12_BITS) {
    unsigned long long int length = 0x6000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x20000;
    uint64_t cap_top = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_TOP;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, cap_top);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_TOP Corner Case
TEST_F(CCheri_lib_tb, GET_TOP_CORNER_CASE) {
    unsigned long long int length = -1;
    uint64_t base = 0x80000000;
    uint64_t addr  = 0x80000100;
    uint64_t cap_top = base + length;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_LEN;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 1;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, length);
}

// Tests GET_BASE for Lengths higher than 12-bits (E=0)
TEST_F(CCheri_lib_tb, GET_BASE_LENGTHS_LOW_12_BITS) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_BASE;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    unsigned long long int length = 0x200;
    uint64_t base = 0x80000000;
    uint64_t addr  = 0x80000100;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

// Tests GET_BASE for Lengths higher than 12-bits (E=52-count_msb_bits(length))
TEST_F(CCheri_lib_tb, GET_BASE_LENGTHS_HIGH_12_BITS) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_BASE;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    // Lengths Higher than 12 bits
    unsigned long long int length = 0x6000;
    uint64_t base = 0x1E000;
    uint64_t addr = 0x20400;
    cap_enc_bounds_t bounds = encode_bounds(base, length, addr);
    top->op_a_int_e_i = bounds.int_e;
    top->op_a_bounds_exp_i = bounds.exp;
    top->op_a_bounds_base_bits_i = bounds.bot_bits;
    top->op_a_bounds_top_bits_i = bounds.top_bits;
    
    top->op_a_addr_i = addr;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, base);
    ASSERT_EQ(top->clu_ex_valid_o,0);
}

TEST_F(CCheri_lib_tb, GET_ADDR) {
    top->fu_data_operator_i  = Vcheri_alu_testharness_ariane_pkg::CGET_BASE;
    top->fu_data_fu_i        = Vcheri_alu_testharness_ariane_pkg::CLU;
    top->set_op_a_full_cap_i = 0;
    top->set_op_b_full_cap_i = 1;
    top->set_pcc_full_cap_i  = 1;
    top->op_a_addr_i = 0x80000000;
    tick(1);
    ASSERT_EQ(top->clu_result_addr_o, 0x80000000);
    ASSERT_EQ(top->clu_ex_valid_o,0);
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

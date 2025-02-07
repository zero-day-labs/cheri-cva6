// Copyright 2018 ETH Zurich and University of Bologna.
// Copyright and related rights are licensed under the Solderpad Hardware
// License, Version 0.51 (the "License"); you may not use this file except in
// compliance with the License.  You may obtain a copy of the License at
// http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
// or agreed to in writing, software, hardware and materials distributed under
// this License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// Author: Florian Zaruba, ETH Zurich
// Date: 09.05.2017
// Description: Branch target calculation and comparison

module branch_unit #(
    parameter config_pkg::cva6_cfg_t CVA6Cfg = config_pkg::cva6_cfg_empty,
    parameter type bp_resolve_t = logic,
    parameter type branchpredict_sbe_t = logic,
    parameter type exception_t = logic,
    parameter type fu_data_t = logic
) (
    // Subsystem Clock - SUBSYSTEM
    input logic clk_i,
    // Asynchronous reset active low - SUBSYSTEM
    input logic rst_ni,
    // Virtualization mode state - CSR_REGFILE
    input logic v_i,
    // Debug mode state - CSR_REGFILE
    input logic debug_mode_i,
    // FU data needed to execute instruction - ISSUE_STAGE
    input fu_data_t fu_data_i,
    // Instruction PC - ISSUE_STAGE
    input logic [CVA6Cfg.PCLEN-1:0] pc_i,
    // Instruction is compressed - ISSUE_STAGE
    input logic is_compressed_instr_i,
    // any functional unit is valid, check that there is no accidental mis-predict - TO_BE_COMPLETED
    input logic fu_valid_i,
    // Branch unit instruction is valid - ISSUE_STAGE
    input logic branch_valid_i,
    // ALU branch compare result - ALU
    input logic branch_comp_res_i,
    // Brach unit result - ISSUE_STAGE
    output logic [CVA6Cfg.REGLEN-1:0] branch_result_o,
    // Information of branch prediction - ISSUE_STAGE
    input branchpredict_sbe_t branch_predict_i,
    // Signaling that we resolved the branch - ISSUE_STAGE
    output bp_resolve_t resolved_branch_o,
    // Branch is resolved, new entries can be accepted by scoreboard - ID_STAGE
    output logic resolve_branch_o,
    // Branch exception out - TO_BE_COMPLETED
    output exception_t branch_exception_o,
    // Branch exception in - CLU Unit
    input exception_t clu_exception_i
);
  logic [CVA6Cfg.PCLEN-1:0] target_address;
  logic [CVA6Cfg.PCLEN-1:0] next_pc;


  // CHERI Signals
  logic cap_mode;
  // Decode input capability operand a and pcc
  cva6_cheri_pkg::cap_pcc_t operand_a;
  cva6_cheri_pkg::cap_pcc_t pcc;
  cva6_cheri_pkg::addrw_t pcc_base;

  // Signals for CHERI exception handling
  cva6_cheri_pkg::cap_pcc_t target_pcc;
  cva6_cheri_pkg::addrw_t target_pcc_base;
  cva6_cheri_pkg::addrwe_t target_pcc_top;
  cva6_cheri_pkg::addrw_t target_pcc_address;
  logic target_pcc_is_sealed;
  assign target_pcc = CVA6Cfg.CheriPresent ? cva6_cheri_pkg::cap_pcc_t'(target_address) : target_address;
  assign pcc = CVA6Cfg.CheriPresent ? cva6_cheri_pkg::cap_pcc_t'(pc_i) : pc_i;
  assign cap_mode = CVA6Cfg.CheriPresent ? (pcc.flags.cap_mode || fu_data_i.operation inside {ariane_pkg::CJALR, ariane_pkg::CINVOKE}) : 1'b0;
  assign operand_a = CVA6Cfg.CheriPresent ? cva6_cheri_pkg::cap_reg_to_cap_pcc(fu_data_i.operand_a) : fu_data_i.operand_a;
  assign pcc_base = CVA6Cfg.CheriPresent ? pcc.base : '0;

  // here we handle the various possibilities of mis-predicts
  always_comb begin : mispredict_handler
    // set the jump base, for JALR we need to look at the register, for all other control flow instructions we can take the current PC
    automatic logic [CVA6Cfg.VLEN-1:0] jump_base;
    automatic logic [CVA6Cfg.VLEN-1:0] jump_base_addr;
    automatic logic [CVA6Cfg.VLEN-1:0] next_pc_off;
    automatic logic [CVA6Cfg.VLEN-1:0] next_pc_addr;
    automatic cva6_cheri_pkg::cap_pcc_t jump_base_cap;
    automatic cva6_cheri_pkg::cap_pcc_t next_pc_tmp, target_address_tmp;
    // TODO(zarubaf): The ALU can be used to calculate the branch target
    jump_base = (fu_data_i.operation inside {ariane_pkg::JALR, ariane_pkg::CJALR, ariane_pkg::CINVOKE}) ? fu_data_i.operand_a[CVA6Cfg.VLEN-1:0] : pc_i[CVA6Cfg.VLEN-1:0];
    jump_base_cap = CVA6Cfg.CheriPresent ? ((fu_data_i.operation inside {ariane_pkg::CJALR, ariane_pkg::CINVOKE}) ? operand_a : pc_i) : '0;
    jump_base_addr = CVA6Cfg.CheriPresent ? ((fu_data_i.operation inside {ariane_pkg::CINVOKE}) ?
                            operand_a.addr :
                            $unsigned($signed(jump_base) + $signed(fu_data_i.imm[CVA6Cfg.VLEN-1:0]))) : '0;

    next_pc_tmp = '0;
    target_address_tmp = '0;
    branch_result_o = CVA6Cfg.CheriPresent ? cva6_cheri_pkg::REG_NULL_CAP : '0;
    resolve_branch_o = 1'b0;
    resolved_branch_o.target_address = '0;
    resolved_branch_o.is_taken = 1'b0;
    resolved_branch_o.valid = branch_valid_i;
    resolved_branch_o.is_mispredict = 1'b0;
    resolved_branch_o.cf_type = branch_predict_i.cf;
    // calculate next PC, depending on whether the instruction is compressed or not this may be different
    // TODO(zarubaf): We already calculate this a couple of times, maybe re-use?
    next_pc_off                      = ((is_compressed_instr_i) ? {{CVA6Cfg.VLEN-2{1'b0}}, 2'h2} : {{CVA6Cfg.VLEN-3{1'b0}}, 3'h4});
    next_pc_addr                     = pc_i[CVA6Cfg.VLEN-1:0] + next_pc_off;
    // Assume that capability is always representable since there is a inbounds check here
    next_pc                          = CVA6Cfg.CheriPresent ? cva6_cheri_pkg::set_cap_pcc_cursor(pcc, next_pc_addr) : next_pc_addr;
    // calculate target address simple 64 bit addition
    if (CVA6Cfg.CheriPresent) begin
    target_address                       = CVA6Cfg.CheriPresent ? cva6_cheri_pkg::set_cap_pcc_cursor(jump_base_cap, jump_base_addr) : '0;
    end else begin
    // calculate target address simple 64 bit addition
    target_address = $unsigned($signed(jump_base) + $signed(fu_data_i.imm[CVA6Cfg.VLEN-1:0]));
    end
    // on a JALR we are supposed to reset the LSB to 0 (according to the specification)
    if (fu_data_i.operation inside {ariane_pkg::CINVOKE, ariane_pkg::JALR, ariane_pkg::CJALR}) target_address[0] = 1'b0;
    if (CVA6Cfg.CheriPresent) begin
    if (!ariane_pkg::op_is_branch(fu_data_i.operation) && cap_mode) begin
        next_pc_tmp = next_pc;
        next_pc_tmp.otype = cva6_cheri_pkg::SENTRY_CAP;
        next_pc = next_pc_tmp;
        if (fu_data_i.operation inside {ariane_pkg::CJALR, ariane_pkg::CINVOKE}) begin
           target_address_tmp =  target_address;
           target_address_tmp.otype = cva6_cheri_pkg::UNSEALED_CAP;
           target_address =  target_address_tmp;
        end
    end
    if (fu_data_i.operation inside {ariane_pkg::CINVOKE}) begin
        next_pc_tmp = fu_data_i.operand_b;
        next_pc_tmp.otype  =  cva6_cheri_pkg::UNSEALED_CAP;
    end else begin
        if (!cap_mode) begin
          next_pc_tmp = cva6_cheri_pkg::set_cap_pcc_cursor(cva6_cheri_pkg::PCC_NULL_CAP, next_pc[CVA6Cfg.VLEN-1:0]);
          next_pc_tmp.tag = 1'b0;
        end else begin
          next_pc_tmp = next_pc;
        end
    end
    branch_result_o = cva6_cheri_pkg::cap_pcc_to_cap_reg(next_pc_tmp);
    end else begin
      // we need to put the branch target address into rd, this is the result of this unit
      branch_result_o = next_pc;
    end
    resolved_branch_o.pc = pc_i[CVA6Cfg.VLEN-1:0];
    // There are only two sources of mispredicts:
    // 1. Branches
    // 2. Jumps to register addresses
    if (branch_valid_i) begin
      // write target address which goes to PC Gen
      resolved_branch_o.target_address = (branch_comp_res_i) ? target_address : next_pc;
      resolved_branch_o.is_taken = branch_comp_res_i;
      // check the outcome of the branch speculation
      if (ariane_pkg::op_is_branch(fu_data_i.operation)) begin
        // Set the `cf_type` of the output as `branch`, this will update the BHT.
        resolved_branch_o.cf_type = ariane_pkg::Branch;
        // If the ALU comparison does not agree with the BHT prediction set the resolution as mispredicted.
        resolved_branch_o.is_mispredict  = branch_comp_res_i != (branch_predict_i.cf == ariane_pkg::Branch);
      end
      if (fu_data_i.operation inside {ariane_pkg::JALR, ariane_pkg::CJALR}
          // check if the address of the jump register is correct and that we actually predicted
          // mispredict in case the PCC metadata changes
          && (branch_predict_i.cf == ariane_pkg::NoCF || target_address[CVA6Cfg.VLEN-1:0] != branch_predict_i.predict_address || (CVA6Cfg.CheriPresent && target_address[CVA6Cfg.CLEN-1:CVA6Cfg.XLEN] != pcc[CVA6Cfg.CLEN-1:CVA6Cfg.XLEN]))) begin
        resolved_branch_o.is_mispredict = 1'b1;
        // update BTB only if this wasn't a return
        if (branch_predict_i.cf != ariane_pkg::Return)
          resolved_branch_o.cf_type = ariane_pkg::JumpR;
      end
      if (fu_data_i.operation inside {ariane_pkg::CINVOKE} && (branch_predict_i.cf == ariane_pkg::NoCF)) begin
          resolved_branch_o.is_mispredict = 1'b1;
      end
      // to resolve the branch in ID
      resolve_branch_o = 1'b1;
    end
  end
  // use ALU exception signal for storing instruction fetch exceptions if
  // the target address is not aligned to a 2 byte boundary
  //
  logic jump_taken;
  always_comb begin : exception_handling
    automatic cva6_cheri_pkg::cap_tval_t cheri_tval;
    // Do a jump if it is either unconditional jump (JAL | JALR) or `taken` conditional jump
    jump_taken = !(ariane_pkg::op_is_branch(fu_data_i.operation)) ||
        ((ariane_pkg::op_is_branch(fu_data_i.operation)) && branch_comp_res_i);
    branch_exception_o.cause = riscv::INSTR_ADDR_MISALIGNED;
    branch_exception_o.valid = 1'b0;
    if (CVA6Cfg.TvalEn)
      branch_exception_o.tval = {{CVA6Cfg.XLEN - CVA6Cfg.VLEN{pc_i[CVA6Cfg.VLEN-1]}}, pc_i};
    else branch_exception_o.tval = '0;
    branch_exception_o.tval2 = {CVA6Cfg.GPLEN{1'b0}};
    branch_exception_o.tinst = '0;
    branch_exception_o.gva   = CVA6Cfg.RVH ? v_i : 1'b0;

     // Decode target address (next PCC) fields
    target_pcc_base       = target_pcc.base;
    target_pcc_top        = target_pcc.top;
    target_pcc_address    = target_pcc.addr;
    target_pcc_is_sealed  = (operand_a.otype != cva6_cheri_pkg::UNSEALED_CAP);
    // Only throw instruction address misaligned exception if this is indeed a `taken` conditional branch or
    // an unconditional jump
    if (branch_valid_i && (target_address[0] || ((!CVA6Cfg.RVC || CVA6Cfg.RVFI_DII) && target_address[1])) && jump_taken) begin
      branch_exception_o.valid = 1'b1;
    end
    if (CVA6Cfg.CheriPresent && branch_valid_i && jump_taken) begin
            if ((fu_data_i.operation inside {ariane_pkg::CJALR} && cap_mode)) begin
                if (target_pcc_base[0] != 1'b0) begin
                    branch_exception_o.cause = cva6_cheri_pkg::CAP_EXCEPTION;
                    cheri_tval.cause         = cva6_cheri_pkg::CAP_UNLIGNED_BASE;
                    cheri_tval.cap_idx       = {6'b100000};
                    branch_exception_o.valid = 1'b1;
                end
            end
            // Check if target address is in bounds
            if (target_pcc_address < target_pcc_base || (target_pcc_address + {{CVA6Cfg.VLEN-2{1'b0}}, 2'h2}) > target_pcc_top) begin
               branch_exception_o.cause = cva6_cheri_pkg::CAP_EXCEPTION;
               cheri_tval.cause         = cva6_cheri_pkg::CAP_LENGTH_VIOLATION;
               cheri_tval.cap_idx       = {6'b100000};
               branch_exception_o.valid = 1'b1;
            end
            if ((fu_data_i.operation inside {ariane_pkg::CJALR})) begin
                if (!operand_a.hperms.permit_execute) begin
                    branch_exception_o.cause = cva6_cheri_pkg::CAP_EXCEPTION;
                    cheri_tval.cause         = cva6_cheri_pkg::CAP_PERM_EXEC_VIOLATION;
                    cheri_tval.cap_idx       = fu_data_i.rs1;
                    branch_exception_o.valid = 1'b1;
                end

                if ((operand_a.otype != cva6_cheri_pkg::UNSEALED_CAP) && (($signed(operand_a.otype) != cva6_cheri_pkg::SENTRY_CAP) || (|fu_data_i.imm[CVA6Cfg.VLEN-1:0]))) begin
                    branch_exception_o.cause = cva6_cheri_pkg::CAP_EXCEPTION;
                    cheri_tval.cause         = cva6_cheri_pkg::CAP_SEAL_VIOLATION;
                    cheri_tval.cap_idx       = fu_data_i.rs1;
                    branch_exception_o.valid = 1'b1;
                end

                if (!operand_a.tag) begin
                    branch_exception_o.cause = cva6_cheri_pkg::CAP_EXCEPTION;
                    cheri_tval.cause         = cva6_cheri_pkg::CAP_TAG_VIOLATION;
                    cheri_tval.cap_idx       = fu_data_i.rs1;
                    branch_exception_o.valid = 1'b1;
                end
            end
        end
        if (CVA6Cfg.CheriPresent && branch_valid_i) begin
            // Check PCC bounds every instruction
            if(pcc.addr < pcc.base || $unsigned(pcc.addr) > pcc.top) begin
               branch_exception_o.cause = cva6_cheri_pkg::CAP_EXCEPTION;
               cheri_tval.cause         = cva6_cheri_pkg::CAP_LENGTH_VIOLATION;
               cheri_tval.cap_idx       = {6'b100000};
               branch_exception_o.valid = 1'b1;
            end
            // Update tval
            branch_exception_o.tval = cheri_tval;
            if (CVA6Cfg.CheriPresent && clu_exception_i.valid && fu_data_i.operation inside {ariane_pkg::CINVOKE}) begin
              branch_exception_o = clu_exception_i;
            end
        end
  end
endmodule

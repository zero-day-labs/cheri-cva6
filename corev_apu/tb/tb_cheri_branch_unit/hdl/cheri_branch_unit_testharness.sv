module cheri_branch_unit_testharness import ariane_pkg::*; import cva6_cheri_pkg::*;#(
) (
    input  logic                     clk_i,         // Clock
    input  logic                     rst_ni,        // Asynchronous reset active low
    input  fu_t                      fu_data_fu_i,
    input  fu_op                     fu_data_operator_i,
    input  logic                     set_op_a_full_cap_i,
    input  bool_t                    op_a_tag_i,
    input  upermsw_t                 op_a_uperms_i,
    input  cap_hperms_t              op_a_hperms_i,
    input  cap_flags_t               op_a_cap_mode_i,
    input  otypew_t                  op_a_otype_i,
    input  cap_fmt_t                 op_a_int_e_i,
    input  ew_t                      op_a_bounds_exp_i,
    input  mw_t                      op_a_bounds_top_bits_i,
    input  mw_t                      op_a_bounds_base_bits_i,
    input  addrw_t                   op_a_addr_i,
    input  logic                     set_op_b_full_cap_i,
    input  bool_t                    op_b_tag_i,
    input  upermsw_t                 op_b_uperms_i,
    input  cap_hperms_t              op_b_hperms_i,
    input  cap_flags_t               op_b_cap_mode_i,
    input  otypew_t                  op_b_otype_i,
    input  cap_fmt_t                 op_b_int_e_i,
    input  ew_t                      op_b_bounds_exp_i,
    input  mw_t                      op_b_bounds_top_bits_i,
    input  mw_t                      op_b_bounds_base_bits_i,
    input  addrw_t                   op_b_addr_i,
    input  riscv::xlen_t             fu_data_imm_i,
    input  logic                     fu_valid_i,
    input  logic                     branch_valid_i,
    input  logic                     branch_comp_res_i, // branch comparison result from ALU
    input  logic                     set_pcc_full_cap_i,
    input  bool_t                    pcc_tag_i,
    input  upermsw_t                 pcc_uperms_i,
    input  cap_hperms_t              pcc_hperms_i,
    input  cap_flags_t               pcc_cap_mode_i,
    input  otypew_t                  pcc_otype_i,
    input  cap_fmt_t                 pcc_int_e_i,
    input  ew_t                      pcc_bounds_exp_i,
    input  mw_t                      pcc_bounds_top_bits_i,
    input  mw_t                      pcc_bounds_base_bits_i,
    input  addrw_t                   pcc_addr_i,
    input  logic                     is_compressed_instr_i,
    input  cf_t                      branch_predict_cf_i,
    input  logic [riscv::VLEN-1:0]   branch_predict_predict_address_i,
    output logic                     resolved_branch_valid_o,           // prediction with all its values is valid
    output logic [riscv::VLEN-1:0]   resolved_branch_pc_o,              // PC of predict or mis-predict
    output bool_t                    resolved_branch_target_address_tag_o,
    output upermsw_t                 resolved_branch_target_address_uperms_o,
    output cap_hperms_t              resolved_branch_target_address_hperms_o,
    output cap_flags_t               resolved_branch_target_address_cap_mode_o,
    output otypew_t                  resolved_branch_target_address_otype_o,
    output cap_fmt_t                 resolved_branch_target_address_int_e_o,
    output ew_t                      resolved_branch_target_address_exp_o,
    output addrw_t                   resolved_branch_target_address_top_o,
    output addrw_t                   resolved_branch_target_address_base_o,
    output addrw_t                   resolved_branch_target_address_addr_o,
    output logic                     resolved_branch_is_mispredict_o,   // set if this was a mis-predict
    output logic                     resolved_branch_is_taken_o,        // branch is taken
    output cf_t                      resolved_branch_cf_type_o,         // Type of control flow change
    output logic                     resolve_branch_o,
    output bool_t                    branch_result_tag_o,
    output upermsw_t                 branch_result_uperms_o,
    output cap_hperms_t              branch_result_hperms_o,
    output cap_flags_t               branch_result_cap_mode_o,
    output otypew_t                  branch_result_otype_o,
    output cap_fmt_t                 branch_result_int_e_o,
    output ew_t                      branch_result_bounds_exp_o,
    output mw_t                      branch_result_bounds_top_bits_o,
    output mw_t                      branch_result_bounds_base_bits_o,
    output addrw_t                   branch_result_addr_o,
    output riscv::xlen_t             branch_ex_cause_o,
    output riscv::xlen_t             branch_ex_tval_o,
    output logic                     branch_ex_valid_o
);
  // Decode PCC fields
  cap_reg_t       pcc_reg_cap;
  cap_pcc_t       pcc_cap;
  cap_reg_t       result;
  exception_t     ex;
  fu_data_t       fu_data;
  branchpredict_sbe_t branch_predict;
  bp_resolve_t        resolved_branch;

  always_comb begin
      pcc_reg_cap = cva6_cheri_pkg::REG_ROOT_CAP;
      if(!set_pcc_full_cap_i) begin
          pcc_reg_cap.tag                 = pcc_tag_i;
          pcc_reg_cap.uperms              = pcc_uperms_i;
          pcc_reg_cap.hperms              = pcc_hperms_i;
          pcc_reg_cap.flags.cap_mode      = pcc_cap_mode_i;
          pcc_reg_cap.otype               = pcc_otype_i;
          pcc_reg_cap.int_e               = pcc_int_e_i;
          pcc_reg_cap.bounds.exp          = pcc_bounds_exp_i;
          pcc_reg_cap.bounds.top_bits     = pcc_bounds_top_bits_i;
          pcc_reg_cap.bounds.base_bits    = pcc_bounds_base_bits_i;
          pcc_reg_cap.addr                = pcc_addr_i;
      end
      pcc_cap = cap_reg_to_cap_pcc(pcc_reg_cap);
      fu_data.operand_a = cva6_cheri_pkg::REG_ROOT_CAP;
      if(!set_op_a_full_cap_i) begin
          fu_data.operand_a.tag                 = op_a_tag_i;
          fu_data.operand_a.uperms              = op_a_uperms_i;
          fu_data.operand_a.hperms              = op_a_hperms_i;
          fu_data.operand_a.flags.cap_mode      = op_a_cap_mode_i;
          fu_data.operand_a.otype               = op_a_otype_i;
          fu_data.operand_a.int_e               = op_a_int_e_i;
          fu_data.operand_a.bounds.exp          = op_a_bounds_exp_i;
          fu_data.operand_a.bounds.top_bits     = op_a_bounds_top_bits_i;
          fu_data.operand_a.bounds.base_bits    = op_a_bounds_base_bits_i;
          fu_data.operand_a.addr                = op_a_addr_i;
      end

      fu_data.operand_b = cva6_cheri_pkg::REG_ROOT_CAP;
      if(!set_op_b_full_cap_i) begin
          fu_data.operand_b.tag                 = op_b_tag_i;
          fu_data.operand_b.uperms              = op_b_uperms_i;
          fu_data.operand_b.hperms              = op_b_hperms_i;
          fu_data.operand_b.flags.cap_mode      = op_b_cap_mode_i;
          fu_data.operand_b.otype               = op_b_otype_i;
          fu_data.operand_b.int_e               = op_b_int_e_i;
          fu_data.operand_b.bounds.exp          = op_b_bounds_exp_i;
          fu_data.operand_b.bounds.top_bits     = op_b_bounds_top_bits_i;
          fu_data.operand_b.bounds.base_bits    = op_b_bounds_base_bits_i;
          fu_data.operand_b.addr                = op_b_addr_i;
      end

      fu_data.fu                    = fu_data_fu_i;
      fu_data.operator              = fu_data_operator_i;
      fu_data.imm                   = fu_data_imm_i;

      branch_predict.cf              = branch_predict_cf_i;
      branch_predict.predict_address = branch_predict_predict_address_i;

      // Output assignments
      // Result Cap
      branch_result_tag_o               = result.tag;
      branch_result_uperms_o            = result.uperms;
      branch_result_hperms_o            = result.hperms;
      branch_result_cap_mode_o          = result.flags.cap_mode;
      branch_result_otype_o             = result.otype;
      branch_result_int_e_o             = result.int_e;
      branch_result_bounds_exp_o        = result.bounds.exp;
      branch_result_bounds_top_bits_o   = result.bounds.top_bits;
      branch_result_bounds_base_bits_o  = result.bounds.base_bits;
      branch_result_addr_o              = result.addr;
      // Exception
      branch_ex_cause_o                 = ex.cause;
      branch_ex_tval_o                  = ex.tval;
      branch_ex_valid_o                 = ex.valid;

      resolved_branch_cf_type_o                   = resolved_branch.cf_type;
      resolved_branch_is_mispredict_o             = resolved_branch.is_mispredict;
      resolved_branch_is_taken_o                  = resolved_branch.is_taken;
      resolved_branch_target_address_tag_o        = resolved_branch.target_address.tag;
      resolved_branch_target_address_uperms_o     = resolved_branch.target_address.uperms;
      resolved_branch_target_address_hperms_o     = resolved_branch.target_address.hperms;
      resolved_branch_target_address_cap_mode_o   = resolved_branch.target_address.flags.cap_mode;
      resolved_branch_target_address_otype_o      = resolved_branch.target_address.otype;
      resolved_branch_target_address_int_e_o      = resolved_branch.target_address.int_e;
      resolved_branch_target_address_exp_o        = resolved_branch.target_address.exp;
      resolved_branch_target_address_top_o        = resolved_branch.target_address.top;
      resolved_branch_target_address_base_o       = resolved_branch.target_address.base;
      resolved_branch_target_address_addr_o       = resolved_branch.target_address.addr;
      resolved_branch_pc_o                        = resolved_branch.pc;
      resolved_branch_valid_o                     = resolved_branch.valid;
  end

  branch_unit branch_unit_cheri(
    .clk_i (clk_i),
    .rst_ni (rst_ni),        // Asynchronous reset active low
    .debug_mode_i (1'b0),
    .fu_data_i (fu_data),
    .pcc_i (pcc_cap),          // Current PCC
    .is_compressed_instr_i (is_compressed_instr_i),
    .fu_valid_i (fu_valid_i),
    .branch_valid_i (branch_valid_i),
    .branch_comp_res_i (branch_comp_res_i),
    .branch_result_o (result),
    .branch_predict_i (branch_predict),
    .resolved_branch_o (resolved_branch),
    .resolve_branch_o (resolve_branch_o),
    .branch_exception_o (ex)     // Return Exception
  );
endmodule
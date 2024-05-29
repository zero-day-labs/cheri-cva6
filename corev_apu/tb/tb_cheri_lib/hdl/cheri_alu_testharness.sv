module cheri_alu_testharness import ariane_pkg::*; import cva6_cheri_pkg::*;#(
) (
    input  logic                     clk_i,         // Clock
    input  logic                     rst_ni,        // Asynchronous reset active low
    input  logic                     v_i,
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
    input  logic                     clu_valid_i,
    input  addrw_t                   alu_result_i,
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
    output bool_t                    clu_result_tag_o,
    output logic [1:0]               clu_result_ct_o,
    output logic [1:0]               clu_result_cb_o,
    output upermsw_t                 clu_result_uperms_o,
    output cap_hperms_t              clu_result_hperms_o,
    output cap_flags_t               clu_result_cap_mode_o,
    output otypew_t                  clu_result_otype_o,
    output cap_fmt_t                 clu_result_int_e_o,
    output ew_t                      clu_result_bounds_exp_o,
    output mw_t                      clu_result_bounds_top_bits_o,
    output mw_t                      clu_result_bounds_base_bits_o,
    output addrw_t                   clu_result_addr_o,
    output riscv::xlen_t             clu_ex_cause_o,
    output riscv::xlen_t             clu_ex_tval_o,
    output logic                     clu_ex_valid_o
);
  // Decode PCC fields
  cap_reg_t       pcc_cap;
  cap_reg_t       result;
  exception_t     ex;
  fu_data_t       fu_data;

  always_comb begin
      pcc_cap = cva6_cheri_pkg::REG_ROOT_CAP;
      if(!set_pcc_full_cap_i) begin
          pcc_cap.tag                 = pcc_tag_i;
          pcc_cap.uperms              = pcc_uperms_i;
          pcc_cap.hperms              = pcc_hperms_i;
          pcc_cap.flags.cap_mode      = pcc_cap_mode_i;
          pcc_cap.otype               = pcc_otype_i;
          pcc_cap.int_e               = pcc_int_e_i;
          pcc_cap.bounds.exp          = pcc_bounds_exp_i;
          pcc_cap.bounds.top_bits     = pcc_bounds_top_bits_i;
          pcc_cap.bounds.base_bits    = pcc_bounds_base_bits_i;
          pcc_cap.addr                = pcc_addr_i;
          pcc_cap.addr_mid            = pcc_addr_i >> pcc_bounds_exp_i;
      end

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
          fu_data.operand_a.addr_mid            = op_a_addr_i >> op_a_bounds_exp_i;
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
          fu_data.operand_b.addr_mid            = op_b_addr_i >> op_b_bounds_exp_i;
      end

      fu_data.fu                    = fu_data_fu_i;
      fu_data.operator              = fu_data_operator_i;
      fu_data.imm                   = fu_data_imm_i;

      // Output assignments
      // Result Cap
      clu_result_tag_o               = result.tag;
      clu_result_uperms_o            = result.uperms;
      clu_result_hperms_o            = result.hperms;
      clu_result_cap_mode_o          = result.flags.cap_mode;
      clu_result_otype_o             = result.otype;
      clu_result_int_e_o             = result.int_e;
      clu_result_bounds_exp_o        = result.bounds.exp;
      clu_result_bounds_top_bits_o   = result.bounds.top_bits;
      clu_result_bounds_base_bits_o  = result.bounds.base_bits;
      clu_result_addr_o              = result.addr;
      // Exception
      clu_ex_cause_o                 = ex.cause;
      clu_ex_tval_o                  = ex.tval;
      clu_ex_valid_o                 = ex.valid;
  end

  cap_pcc_t pcc;

  assign pcc = cap_reg_to_cap_pcc(pcc_cap);

  cheri_unit cheri(
    .clk_i (clk_i),
    .rst_ni (rst_ni),        // Asynchronous reset active low
    .v_i (v_i),
    .fu_data_i (fu_data),
    .pcc_i (pcc),          // Current PCC
    .clu_valid_i (clu_valid_i),
    .alu_result_i (alu_result_i),
    .clu_result_o (result),  // Return resulting cap
    .clu_ex_o (ex)     // Return Exception
  );
endmodule

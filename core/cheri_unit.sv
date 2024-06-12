// Copyright 2022 Bruno Sá and Zero-Day Labs.
// Copyright and related rights are licensed under the Solderpad Hardware
// License, Version 0.51 (the "License"); you may not use this file except in
// compliance with the License.  You may obtain a copy of the License at
// http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
// or agreed to in writing, software, hardware and materials distributed under
// this License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions ansd limitations under the License.
//
// Author: Bruno Sá <bruno.vilaca.sa@gmail.com>
// Acknowledges: Technology Inovation Institute (TII)
//
// Date: 02.09.2022
// Description: CVA6 CHERI Logic Unit


module cheri_unit import ariane_pkg::*; import cva6_cheri_pkg::*;#(
    parameter config_pkg::cva6_cfg_t CVA6Cfg       = config_pkg::cva6_cfg_empty,
    parameter type fu_data_t = logic,
    parameter type exception_t = logic,
    parameter int CHERI_ISA_V8       = 0
    ) (
    input  logic                     clk_i,         // Clock
    input  logic                     rst_ni,        // Asynchronous reset active low
    input  logic                     v_i ,
    input  fu_data_t                 fu_data_i,
    input  cap_pcc_t                 pcc_i,          // Current PCC
    input  logic                     clu_valid_i,
    input  addrw_t                   alu_result_i,
    output cap_reg_t                 clu_result_o,  // Return resulting cap
    output exception_t               clu_ex_o       // Return Exception
);
    // operand a decode fields
    cap_reg_t operand_a;
    addrw_t operand_a_base;
    addrwe_t operand_a_top;
    addrwe_t operand_a_length;
    addrw_t operand_a_offset;
    addrw_t operand_a_address;
    logic operand_a_is_sealed;
    logic is_operand_a_rev_otype;
    cap_meta_data_t op_a_meta_info;

    // operand b decode fields
    cap_reg_t operand_b;
    addrw_t operand_b_base;
    addrwe_t operand_b_top;
    addrwe_t operand_b_length;
    addrw_t operand_b_address;
    addrw_t operand_b_offset;
    logic operand_b_is_sealed;
    logic is_operand_b_rev_otype;
    cap_meta_data_t op_b_meta_info;

    // operand pcc decode meta data
    cap_reg_t      pcc;
    cap_meta_data_t op_pc_meta_info;

    // Common operations signals
    // Set address operations signals
    addrw_t address;
    cap_reg_t op_set_addr;
    cap_meta_data_t op_meta_set_addr;
    cap_reg_t res_set_addr;
    // Operation set/inc offset signals
    cap_reg_t op_set_offset;
    cap_meta_data_t op_meta_set_offset;
    bool_t set_offset;
    addrw_t   offset;
    cap_reg_t res_set_offset;
    // Operation set bounds;
    addrw_t set_bounds_base;
    addrwe_t set_bounds_len, set_bounds_top;
    cap_reg_t op_set_bounds;
    cap_reg_set_bounds_ret_t res_set_bounds;
    cap_meta_data_t res_set_bounds_meta_data;

    // Exception signals
    logic [CAP_EXP_NUM-1:0] operand_a_violations;
    logic [CAP_EXP_NUM-1:0] operand_b_violations;
    logic [CAP_EXP_NUM-1:0] check_operand_a_violations;
    logic [CAP_EXP_NUM-1:0] check_operand_b_violations;
    logic en_ex;

    // Output signals
    cap_reg_t clu_result;

    assign pcc = cap_pcc_to_cap_reg(pcc_i);
    // -----------
    // CHERI ALU main logic circuit
    // -----------
    always_comb begin
        automatic cap_reg_t tmp_cap;

        // exceptions signals reset
        check_operand_a_violations = {CAP_EXP_NUM{1'b0}};
        check_operand_b_violations = {CAP_EXP_NUM{1'b0}};
        en_ex                      = 1'b0;

        // Set address operation reset signals
        op_set_addr                = operand_a;
        op_meta_set_addr           = op_a_meta_info;
        address                    = '{default:0};

        // Set offset operation reset signals
        op_set_offset              = operand_a;
        op_meta_set_offset         = op_a_meta_info;
        set_offset                 = 1'b0;
        offset                     = '{default:0};

        // Set bounds operation reset signals
        op_set_bounds              = operand_a;
        set_bounds_base            = '{default:0};
        set_bounds_top             = '{default:0};
        set_bounds_len             = '{default:0};

        // Output reset values
        clu_result                 = REG_NULL_CAP;

        // Auxiliar signals
        tmp_cap                    = REG_NULL_CAP;

        unique case (fu_data_i.operation)
            // AUIPCC
            // TODO:change this to offset maybe
            ariane_pkg::AUIPCC: begin
                address          = alu_result_i;
                op_set_addr      = pcc;
                op_meta_set_addr = op_pc_meta_info;
                clu_result       = res_set_addr;
            end
            // CAndPerm
            ariane_pkg::CAND_PERM: begin
                en_ex = (CHERI_ISA_V8 == 1) ? 1'b1 : 1'b0;
                check_operand_a_violations = ((1 << CAP_TAG_VIOLATION) && CHERI_ISA_V8) |
                                             (1 << CAP_SEAL_VIOLATION);
                tmp_cap = operand_a;
                tmp_cap.uperms = (tmp_cap.uperms & (operand_b_address[CAP_UPERMS_WIDTH+CAP_UPERMS_SHIFT-1:CAP_UPERMS_SHIFT]));
                tmp_cap.hperms = cap_hperms_t'(tmp_cap.hperms & operand_b_address[CAP_HPERMS_WIDTH-1:0]);
                clu_result = tmp_cap;
            end
            // CBuildCap
            // TODO: units tests
            ariane_pkg::CBUILD_CAP: begin
                tmp_cap  = operand_b;
                tmp_cap.otype = (operand_b.otype == SENTRY_CAP) ? SENTRY_CAP : UNSEALED_CAP;
                tmp_cap.tag = 1'b1;
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);

                // Set bounds
                set_bounds_base = operand_b_base;
                set_bounds_len =  operand_b_top - operand_b_base;
                set_bounds_top = {1'b0,set_bounds_base} + set_bounds_len;
                op_set_bounds = tmp_cap;
                // Set offset
                address = operand_b_address;
                offset = operand_b_offset;
                op_set_offset = res_set_bounds.cap;
                op_meta_set_offset = res_set_bounds_meta_data;
                set_offset = 1'b1;
                tmp_cap = res_set_offset;

                // Set permission bits
                tmp_cap.uperms = operand_b.uperms & operand_a.uperms;
                tmp_cap.hperms = operand_b.hperms & operand_a.hperms;
                tmp_cap.flags.cap_mode = operand_b.flags.cap_mode;

                if( (tmp_cap == operand_b)                          &&
                    !operand_b_violations[CAP_LENGTH_VIOLATION]     &&
                    !operand_b_violations[CAP_USER_DEF_PERM_VIOLATION])
                    clu_result = tmp_cap;
                else begin
                    clu_result = operand_b;
                    clu_result.tag = 1'b0;
                end
            end
            // CClearTag
            ariane_pkg::CCLEAR_TAG: begin
                tmp_cap = operand_a;
                // clear operand_a capability tag bit
                tmp_cap.tag = 1'b0;
                clu_result = tmp_cap;
            end
            // CCopyType
            ariane_pkg::CCOPY_TYPE: begin
                en_ex = 0;
                op_set_addr = operand_a;
                op_meta_set_addr = op_a_meta_info;
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);

                if(is_operand_b_rev_otype) begin
                    address = $signed(operand_b.otype);
                end else begin
                    address = $unsigned(operand_b.otype);
                end
                tmp_cap = res_set_addr;
                clu_result = tmp_cap;
            end
            // CCSeal
            ariane_pkg::CCSEAL: begin
                if( operand_b_violations[CAP_TAG_VIOLATION]         ||
                    operand_a_violations[CAP_SEAL_VIOLATION]        ||
                    operand_b_violations[CAP_LENGTH_VIOLATION]      ||
                    ($signed(operand_b_address) == UNSEALED_CAP)) begin
                    tmp_cap = operand_a;
                end else begin
                    check_operand_b_violations = (1 << CAP_SEAL_VIOLATION)      |
                                                 (1 << CAP_PERM_SEAL)           |
                                                 (1 << CAP_TYPE_VIOLATION);
                    tmp_cap       = operand_a;
                    tmp_cap.otype = operand_b_address[CAP_OTYPE_WIDTH-1:0];
                end
                clu_result  = tmp_cap;
            end
            // CFromPtr
            // TODO: need to check if cs1 == 0 then use DDC
            ariane_pkg::CFROM_PTR: begin
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);
                op_set_offset = operand_a;
                offset = operand_b_address;
                op_meta_set_offset = op_a_meta_info;
                set_offset = 1'b1;
                address = operand_a_base + operand_b_address;
                if((|operand_b_address)) begin
                    tmp_cap = res_set_offset;
                end else begin
                    tmp_cap = REG_NULL_CAP;
                end
                clu_result = tmp_cap;
            end
            // CGetAddr
            ariane_pkg::CGET_ADDR: begin
                clu_result.addr = operand_a_address;
            end
            // CGetBase
            ariane_pkg::CGET_BASE: begin
                clu_result.addr = operand_a_base;
            end
            // CGetTop
            ariane_pkg::CGET_TOP: begin
                clu_result.addr = operand_a_top[CVA6Cfg.XLEN-1:0];
            end
            // CGetFlags
            ariane_pkg::CGET_FLAGS: begin
                clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}},operand_a.flags};
            end
            // CGetFlags
            ariane_pkg::CGET_LEN: begin
                clu_result.addr = operand_a_length[CVA6Cfg.XLEN-1:0];
            end
            // CGetOffset
            ariane_pkg::CGET_OFFSET: begin
                clu_result.addr = operand_a_offset;
            end
            // CGetPerm
            ariane_pkg::CGET_PERM: begin
                clu_result.addr = {{CVA6Cfg.XLEN-19{1'b0}},
                                      operand_a.uperms,
                                      3'b000,
                                      operand_a.hperms
                                    };
            end
            // CGetSealed
            ariane_pkg::CGET_SEALED: begin
                clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}},operand_a_is_sealed};
            end
            // CGetTag
            ariane_pkg::CGET_TAG: begin
                clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}},operand_a.tag};
            end
            // CGetType
            ariane_pkg::CGET_TYPE: begin
                if(operand_a.otype >= OTYPE_MAX)
                    clu_result.addr = $signed(operand_a.otype);
                else
                    clu_result.addr = $unsigned(operand_a.otype);
            end
            // CIncOffset and CIncOffsetImm
            // TODO: use ALU to calculate address
            ariane_pkg::CINC_OFFSET,ariane_pkg::CINC_OFFSET_IMM: begin
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);
                offset = operand_b_address;
                op_set_offset = operand_a;
                op_meta_set_offset = op_a_meta_info;
                set_offset = 1'b0;
                offset = ((fu_data_i.operation == ariane_pkg::CINC_OFFSET) ? operand_b_address : fu_data_i.imm);
                address = operand_a_address + offset;
                tmp_cap = res_set_offset;
                clu_result = tmp_cap;
            end
            // CINVOKE
            ariane_pkg::CINVOKE: begin
                en_ex = 1'b1;
                check_operand_a_violations = (1 << CAP_TAG_VIOLATION)       |
                                             (1 << CAP_SEAL_VIOLATION)      |
                                             (1 << CAP_PERM_CINVOKE)        |
                                             (1 << CAP_PERM_EXEC_VIOLATION) |
                                             (1 << CAP_UNLIGNED_BASE);
                check_operand_b_violations = (1 << CAP_TAG_VIOLATION)       |
                                             (1 << CAP_SEAL_VIOLATION)      |
                                             (1 << CAP_TYPE_VIOLATION)      |
                                             (1 << CAP_PERM_CINVOKE)        |
                                             (1 << CAP_PERM_EXEC_VIOLATION);
            end
            // CMove
            ariane_pkg::CMOVE: begin
                clu_result = operand_a;
            end
            // CSeal
            ariane_pkg::CSEAL: begin
                clu_result  = operand_a;
                check_operand_a_violations = (1 << CAP_TAG_VIOLATION)  |
                                             (1 << CAP_SEAL_VIOLATION);
                check_operand_b_violations = (1 << CAP_TAG_VIOLATION)  |
                                             (1 << CAP_SEAL_VIOLATION) |
                                             (1 << CAP_PERM_SEAL)      |
                                             (1 << CAP_TYPE_VIOLATION) |
                                             (1 << CAP_LENGTH_VIOLATION);
                clu_result.otype = operand_b_address[CAP_OTYPE_WIDTH-1:0];
            end
            // CSealEntry
            ariane_pkg::CSEAL_ENTRY: begin
                // NOTE: for CHERI ISAv8 we need to do this checks
                if (CHERI_ISA_V8) begin
                    check_operand_a_violations = (1 << CAP_TAG_VIOLATION)       |
                                                 (1 << CAP_SEAL_VIOLATION)      |
                                                 (1 << CAP_PERM_EXEC_VIOLATION);
                end else begin
                    check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);
                end
                clu_result = operand_a;
                clu_result.otype = SENTRY_CAP;
            end
            // CSetAddr
            ariane_pkg::CSET_ADDR: begin
                en_ex =  1'b0;
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);
                op_set_addr  = operand_a;
                op_meta_set_addr = op_a_meta_info;
                address      = operand_b.addr;
                clu_result = res_set_addr;
            end
            // CSetBounds, CSetBoundsExact, CSetBoundsImm,
            // CRepresentableAlignmentMask and CRepresentableLength
            ariane_pkg::CSET_BOUNDS,
            ariane_pkg::CSET_BOUNDS_EXACT,
            ariane_pkg::CSET_BOUNDS_IMM,
            ariane_pkg::CRND_REPRESENTABLE_LEN,
            ariane_pkg::CRND_REPRESENTABLE_ALIGN_MSK: begin
                if (fu_data_i.operation inside {ariane_pkg::CRND_REPRESENTABLE_LEN,ariane_pkg::CRND_REPRESENTABLE_ALIGN_MSK}) begin
                   set_bounds_base = 0;
                   set_bounds_len = $unsigned(operand_a_address);
                   set_bounds_top = set_bounds_len;
                end else begin
                    set_bounds_base = operand_a_address;
                    set_bounds_len =  ((fu_data_i.operation == ariane_pkg::CSET_BOUNDS_IMM) ? fu_data_i.imm : $unsigned(operand_b_address));
                    set_bounds_top = {1'b0,set_bounds_base} + set_bounds_len;
                    check_operand_a_violations = (1 << CAP_TAG_VIOLATION)   |
                                                 (1 << CAP_LENGTH_VIOLATION);
                end
                op_set_bounds = operand_a;
                if (fu_data_i.operation == ariane_pkg::CRND_REPRESENTABLE_LEN)
                    clu_result.addr = res_set_bounds.length[CAP_ADDR_WIDTH-1:0];
                else if (fu_data_i.operation == ariane_pkg::CRND_REPRESENTABLE_ALIGN_MSK)
                    clu_result.addr = res_set_bounds.mask;
                else
                    clu_result = res_set_bounds.cap;

                if ((!res_set_bounds.exact && fu_data_i.operation == ariane_pkg::CSET_BOUNDS_EXACT))
                    clu_result.tag = 1'b0;
            end
            // CSetEqualExact
            ariane_pkg::CSET_EQUAL_EXACT: begin
                clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, (operand_a == operand_b) ? 1'b1 : 1'b0};
            end
            // CSetFlags
            ariane_pkg::CSET_FLAGS: begin
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);
                tmp_cap = operand_a;
                tmp_cap.flags.cap_mode = operand_b.addr[0];
                clu_result = tmp_cap;
            end
            // CSetOffset
            // TODO: - use ALU to compute offset
            //       - implement cap_inc_offset somehere else to avoid logic replication
            ariane_pkg::CSET_OFFSET: begin
                check_operand_a_violations = (1 << CAP_SEAL_VIOLATION);
                address = operand_a_base + operand_b_address;
                offset = operand_b_address;
                op_set_offset = operand_a;
                op_meta_set_offset = op_a_meta_info;
                set_offset = 1'b1;
                tmp_cap = res_set_offset;
                clu_result = tmp_cap;
            end
            // CSub
            ariane_pkg::CSUB: begin
                clu_result.addr = operand_a_address - operand_b_address;
            end
            // CTestSubset
            ariane_pkg::CTEST_SUBSET: begin
                clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b1};
                if(operand_a.tag != operand_b.tag) begin
                    clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b0};
                end
                if(operand_b_base < operand_a_base) begin
                    clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b0};
                end
                if(operand_b_top > operand_a_top) begin
                    clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b0};
                end
                if(operand_b_top > operand_a_top) begin
                    clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b0};
                end
                if((operand_a.uperms & operand_b.uperms) != operand_b.uperms) begin
                    clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b0};
                end
                if((operand_a.hperms & operand_b.hperms) != operand_b.hperms) begin
                    clu_result.addr = {{CVA6Cfg.XLEN-1{1'b0}}, 1'b0};
                end
            end
            // CToPtr
            // TODO-cheri ninolomata: operand_b is equal to DDC when operand_b idx is 0
            // TODO-cheri ninolomata: use ALU to compute address
            ariane_pkg::CTO_PTR: begin
                check_operand_a_violations = (1 << CAP_TAG_VIOLATION);
                if(operand_a_violations[CAP_TAG_VIOLATION]) begin
                    clu_result.addr = {{CVA6Cfg.XLEN{1'b0}}};
                end else begin
                    clu_result.addr = operand_a_address - operand_b_base;
                end
            end
            // CUnseal
            ariane_pkg::CUNSEAL: begin
                check_operand_a_violations = (1 << CAP_TAG_VIOLATION)   |
                                             (1 << CAP_SEAL_VIOLATION)  |
                                             (1 << CAP_TYPE_VIOLATION);

                check_operand_b_violations = (1 << CAP_TAG_VIOLATION)   |
                                             (1 << CAP_SEAL_VIOLATION)  |
                                             (1 << CAP_TYPE_VIOLATION)  |
                                             (1 << CAP_PERM_UNSEAL)     |
                                             (1 << CAP_LENGTH_VIOLATION);
                tmp_cap = operand_a;
                tmp_cap.hperms.gbl = tmp_cap.hperms.gbl & operand_b.hperms.gbl;
                tmp_cap.otype = UNSEALED_CAP;
                clu_result = tmp_cap;
            end
            default: ; // default case to suppress unique warning
        endcase

        // Update destination register

    end

    // ----------------
    // Decode Cap Operands Fields
    // ----------------
    always_comb begin
        // Decode capability operand a fields
        operand_a = fu_data_i.operand_a;
        op_a_meta_info = get_cap_reg_meta_data(operand_a);
        operand_a_address = operand_a.addr;
        operand_a_base   = get_cap_reg_base(operand_a, op_a_meta_info);
        operand_a_top    = get_cap_reg_top(operand_a, op_a_meta_info);
        operand_a_length = get_cap_reg_length(operand_a, op_a_meta_info);
        operand_a_offset = get_cap_reg_offset(operand_a, op_a_meta_info);
        operand_a_is_sealed = (operand_a.otype != UNSEALED_CAP);
        is_operand_a_rev_otype = operand_a.otype > OTYPE_MAX;
        // Decode capability operand b fields
        operand_b = fu_data_i.operand_b;
        operand_b_address = operand_b.addr;
        op_b_meta_info = get_cap_reg_meta_data(operand_b);
        operand_b_base   = get_cap_reg_base(operand_b, op_b_meta_info);
        operand_b_top    = get_cap_reg_top(operand_b, op_b_meta_info);
        operand_b_length = get_cap_reg_length(operand_b, op_b_meta_info);
        operand_b_offset = get_cap_reg_offset(operand_b, op_b_meta_info);
        operand_b_is_sealed = (operand_b.otype != UNSEALED_CAP);
        is_operand_b_rev_otype = operand_b.otype > OTYPE_MAX;
        // Decode pc metadata fields
        op_pc_meta_info = get_cap_reg_meta_data(pcc);
        // Decode bounds from set cap reg bounds, needed for the CBUILDCAP instruction
        res_set_bounds_meta_data = get_cap_reg_meta_data(res_set_bounds.cap);
    end

    // ----------------
    // Common Operations
    // 1. Set address operation
    // 2. Set offset operation
    // ----------------
    always_comb begin
        res_set_addr = set_cap_reg_address(op_set_addr,
                                           address,
                                           op_meta_set_addr
                                        );

        res_set_offset = cap_reg_inc_offset(op_set_offset,
                                            address,
                                            offset,
                                            op_meta_set_offset,
                                            set_offset
                                        );
        res_set_bounds = set_cap_reg_bounds(op_set_bounds, set_bounds_base, set_bounds_len);
    end

    // ----------------
    // Operands Exception Control Checks
    // ----------------
    always_comb begin
        operand_a_violations = {CAP_EXP_NUM{1'b0}};
        operand_b_violations = {CAP_EXP_NUM{1'b0}};
        // Operand a capability checks
        if (!is_cap_reg_valid(fu_data_i.operand_a)) begin
            operand_a_violations[CAP_TAG_VIOLATION] = 1'b1;
        end

        if (operand_a_is_sealed) begin
            operand_a_violations[CAP_SEAL_VIOLATION] = 1'b1;
        end

        if (!is_cap_reg_valid(fu_data_i.operand_b)) begin
            operand_b_violations[CAP_TAG_VIOLATION] = 1'b1;
        end

        if (operand_b_is_sealed) begin
            operand_b_violations[CAP_SEAL_VIOLATION] = 1'b1;
        end

        if ((fu_data_i.operation inside {ariane_pkg::CBUILD_CAP})) begin
            if (operand_b_base < operand_a_base) begin
                operand_b_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if (operand_b_top > operand_a_top) begin
                operand_b_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if (operand_b_base > operand_a_top) begin
                operand_b_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if ((operand_a.uperms & operand_b.uperms) != operand_b.uperms) begin
                operand_b_violations[CAP_USER_DEF_PERM_VIOLATION] = 1'b1;
            end

            if ((operand_a.hperms & operand_b.hperms) != operand_b.hperms) begin
                operand_b_violations[CAP_USER_DEF_PERM_VIOLATION] = 1'b1;
            end

            /* if ((operand_b.otype & operand_b.hperms) != operand_b.hperms) begin
                operand_a_violations[CAP_USER_DEF_PERM_VIOLATION] = 1'b1;
            end */
        end

        if ((fu_data_i.operation inside {ariane_pkg::CCSEAL,ariane_pkg::CSEAL})) begin
            if (operand_b_address > OTYPE_MAX) begin
                operand_b_violations[CAP_TYPE_VIOLATION] = 1'b1;
            end

            if (!operand_b.hperms.permit_seal) begin
                operand_b_violations[CAP_PERM_SEAL] = 1'b1;
            end
        end

        if ((fu_data_i.operation inside {ariane_pkg::CCSEAL,ariane_pkg::CSEAL,ariane_pkg::CUNSEAL})) begin
            if (operand_b_address < operand_b_base) begin
                operand_b_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if (operand_b_address >= operand_b_top) begin
                operand_b_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end
        end

        if (fu_data_i.operation inside {ariane_pkg::CCOPY_TYPE}) begin
            if (operand_b.otype < operand_a_base) begin
                operand_a_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if (operand_b.otype >= operand_a_top) begin
                operand_a_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end
        end

        if ((fu_data_i.operation inside {ariane_pkg::CSET_BOUNDS,ariane_pkg::CSET_BOUNDS_EXACT,ariane_pkg::CSET_BOUNDS_IMM})) begin
            if (operand_a_address < operand_a_base) begin
                operand_a_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if ((set_bounds_top) > operand_a_top) begin
                operand_a_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end
        end

        if ((fu_data_i.operation inside {ariane_pkg::CUNSEAL})) begin
            if (is_operand_a_rev_otype) begin
                operand_a_violations[CAP_TYPE_VIOLATION] = 1'b1;
            end

            if (operand_b_address != $unsigned(operand_a.otype)) begin
                operand_b_violations[CAP_TYPE_VIOLATION] = 1'b1;
            end
            if (!operand_b.hperms.permit_unseal) begin
                operand_b_violations[CAP_PERM_UNSEAL] = 1'b1;
            end

            if (!operand_a_is_sealed) begin
                operand_a_violations[CAP_SEAL_VIOLATION] = 1'b1;
            end else begin
                operand_a_violations[CAP_SEAL_VIOLATION] = 1'b0;
            end
        end

        if ((fu_data_i.operation inside {ariane_pkg::CINVOKE})) begin
            if (operand_a.otype != operand_b.otype) begin
                operand_a_violations[CAP_TYPE_VIOLATION] = 1'b1;
            end

            if((operand_a_address < operand_a_base) || ((operand_a_address + {{riscv::VLEN-2{1'b0}}, 2'h2}) > operand_a_top)) begin
                operand_a_violations[CAP_LENGTH_VIOLATION] = 1'b1;
            end

            if ((operand_a_base[0] != 1'b0)) begin
                operand_a_violations[CAP_UNLIGNED_BASE] = 1'b1;
            end

            if (is_operand_a_rev_otype) begin
                operand_a_violations[CAP_SEAL_VIOLATION] = 1'b1;
            end else begin
                operand_a_violations[CAP_SEAL_VIOLATION] = 1'b0;
            end

            if (is_operand_b_rev_otype) begin
                operand_b_violations[CAP_SEAL_VIOLATION] = 1'b1;
            end else begin
                operand_b_violations[CAP_SEAL_VIOLATION] = 1'b0;
            end

        end
    end

    // ------------------------
    // CHERI Output Logic
    // ------------------------
    always_comb begin: cheri_output_logic
        clu_result_o = clu_result;
        // Clear result capability tag if there was any violations
        if ((operand_a_violations & check_operand_a_violations)  > 0 ||
            (operand_b_violations & check_operand_b_violations) > 0) begin
            clu_result_o.tag = 1'b0;
        end
    end

    // ------------------------
    // CHERI Exception Control
    // ------------------------
    always_comb begin: cheri_exception_control
        automatic cap_tval_t cheri_tval;
        cheri_tval     = {CVA6Cfg.XLEN{1'b0}};
        clu_ex_o.cause = CAP_EXCEPTION;
        clu_ex_o.valid = 1'b0;
        clu_ex_o.tval  = {CVA6Cfg.XLEN{1'b0}};
        clu_ex_o.tval2 = {CVA6Cfg.XLEN{1'b0}};
        clu_ex_o.tinst = {CVA6Cfg.XLEN{1'b0}};
        clu_ex_o.gva   = v_i;

        // TODO-cheri ninolomata: Update the cap_idx in the tval value
        if(clu_valid_i) begin
            if(operand_a_violations[CAP_REPRE_VIOLATION] & check_operand_a_violations[CAP_REPRE_VIOLATION]) begin
                cheri_tval.cause   = CAP_REPRE_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_UNLIGNED_BASE] & check_operand_a_violations[CAP_UNLIGNED_BASE]) begin
                cheri_tval.cause   = CAP_UNLIGNED_BASE;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_USER_DEF_PERM_VIOLATION] & check_operand_a_violations[CAP_USER_DEF_PERM_VIOLATION]) begin
                cheri_tval.cause   = CAP_USER_DEF_PERM_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_LENGTH_VIOLATION] & check_operand_b_violations[CAP_LENGTH_VIOLATION]) begin
                cheri_tval.cause   = CAP_LENGTH_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_LENGTH_VIOLATION] & check_operand_a_violations[CAP_LENGTH_VIOLATION]) begin
                cheri_tval.cause   = CAP_LENGTH_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_REPRE_VIOLATION] & check_operand_a_violations[CAP_REPRE_VIOLATION]) begin
                cheri_tval.cause   = CAP_REPRE_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_GLOBAL_VIOLATION] & check_operand_a_violations[CAP_GLOBAL_VIOLATION]) begin
                cheri_tval.cause   = CAP_LENGTH_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_GLOBAL_VIOLATION] & check_operand_a_violations[CAP_GLOBAL_VIOLATION]) begin
                cheri_tval.cause   = CAP_GLOBAL_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_ST_CAP_LOCAL_VIOLATION] & check_operand_a_violations[CAP_PERM_ST_CAP_LOCAL_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_ST_CAP_LOCAL_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_ST_CAP_VIOLATION] & check_operand_a_violations[CAP_PERM_ST_CAP_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_ST_CAP_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_LD_CAP_VIOLATION] & check_operand_a_violations[CAP_PERM_LD_CAP_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_LD_CAP_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_ST_VIOLATION] & check_operand_a_violations[CAP_PERM_ST_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_ST_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_LD_VIOLATION] & check_operand_a_violations[CAP_PERM_LD_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_LD_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_PERM_EXEC_VIOLATION] & check_operand_b_violations[CAP_PERM_EXEC_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_EXEC_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_EXEC_VIOLATION] & check_operand_a_violations[CAP_PERM_EXEC_VIOLATION]) begin
                cheri_tval.cause   = CAP_PERM_EXEC_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_SET_CID] & check_operand_a_violations[CAP_PERM_SET_CID]) begin
                cheri_tval.cause   = CAP_PERM_SET_CID;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_PERM_UNSEAL] & check_operand_b_violations[CAP_PERM_UNSEAL]) begin
                cheri_tval.cause   = CAP_PERM_UNSEAL;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_UNSEAL] & check_operand_a_violations[CAP_PERM_UNSEAL]) begin
                cheri_tval.cause   = CAP_PERM_UNSEAL;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_ACCESS_CINVOKE_IDC] & check_operand_a_violations[CAP_PERM_ACCESS_CINVOKE_IDC]) begin
                cheri_tval.cause   = CAP_PERM_ACCESS_CINVOKE_IDC;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_PERM_CINVOKE] & check_operand_b_violations[CAP_PERM_CINVOKE]) begin
                cheri_tval.cause   = CAP_PERM_CINVOKE;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_CINVOKE] & check_operand_a_violations[CAP_PERM_CINVOKE]) begin
                cheri_tval.cause   = CAP_PERM_CINVOKE;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_PERM_SEAL] & check_operand_b_violations[CAP_PERM_SEAL]) begin
                cheri_tval.cause   = CAP_PERM_SEAL;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_PERM_SEAL] & check_operand_a_violations[CAP_PERM_SEAL]) begin
                cheri_tval.cause   = CAP_PERM_SEAL;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_TYPE_VIOLATION] & check_operand_b_violations[CAP_TYPE_VIOLATION]) begin
                cheri_tval.cause   = CAP_TYPE_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_TYPE_VIOLATION] & check_operand_a_violations[CAP_TYPE_VIOLATION]) begin
                cheri_tval.cause   = CAP_TYPE_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_SEAL_VIOLATION] & check_operand_b_violations[CAP_SEAL_VIOLATION]) begin
                cheri_tval.cause   = CAP_SEAL_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_SEAL_VIOLATION] & check_operand_a_violations[CAP_SEAL_VIOLATION]) begin
                cheri_tval.cause   = CAP_SEAL_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_b_violations[CAP_TAG_VIOLATION] & check_operand_b_violations[CAP_TAG_VIOLATION]) begin
                cheri_tval.cause   = CAP_TAG_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end
            if(operand_a_violations[CAP_TAG_VIOLATION] & check_operand_a_violations[CAP_TAG_VIOLATION]) begin
                cheri_tval.cause   = CAP_TAG_VIOLATION;
                clu_ex_o.valid     = 1'b1;
            end

            // Update tval
            clu_ex_o.valid &= en_ex;
            clu_ex_o.tval = $unsigned(cheri_tval.cause);
        end
    end
endmodule

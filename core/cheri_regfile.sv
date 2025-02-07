// Copyright 2018 ETH Zurich and University of Bologna.
// Copyright 2025 Bruno Sá and Zero-Day Labs.
// Copyright and related rights are licensed under the Solderpad Hardware
// License, Version 0.51 (the "License"); you may not use this file except in
// compliance with the License.  You may obtain a copy of the License at
// http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
// or agreed to in writing, software, hardware and materials distributed under
// this License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// Engineer:       Francesco Conti - f.conti@unibo.it
//
// Additional contributions by:
//                 Markus Wegmann - markus.wegmann@technokrat.ch
//
// Design Name:    RISC-V register file
// Project Name:   zero-riscy
// Language:       SystemVerilog
//
// Description:    Register file with 31 or 15x 32 bit wide registers.
//                 Register 0 is fixed to 0. This register file is based on
//                 flip flops.
//

module cheri_regfile #(
    parameter config_pkg::cva6_cfg_t CVA6Cfg       = config_pkg::cva6_cfg_empty,
    parameter int unsigned           DATA_WIDTH    = 32,
    parameter int unsigned           NR_READ_PORTS = 2,
    parameter bit                    ZERO_REG_ZERO = 0
) (
    // clock and reset
    input  logic                                             clk_i,
    input  logic                                             rst_ni,
    // disable clock gates for testing
    input  logic                                             test_en_i,
    // read port
    input  logic [        NR_READ_PORTS-1:0][           4:0] raddr_i,
    output logic [        NR_READ_PORTS-1:0][DATA_WIDTH-1:0] rdata_o,
    // write port
    input  logic [CVA6Cfg.NrCommitPorts-1:0][           4:0] waddr_i,
    input  logic [CVA6Cfg.NrCommitPorts-1:0][DATA_WIDTH-1:0] wdata_i,
    input  logic [CVA6Cfg.NrCommitPorts-1:0]                 we_i,
    input  logic [CVA6Cfg.NrCommitPorts-1:0]                 clr_i,
    input  logic [CVA6Cfg.NrCommitPorts-1:0][7:0]            mask_i,   // mask bit
    input  logic [CVA6Cfg.NrCommitPorts-1:0][1:0]            quarter_i // quarter selection
);

  localparam ADDR_WIDTH = 5;
  localparam NUM_WORDS = 2 ** ADDR_WIDTH;

  logic [            NUM_WORDS-1:0][DATA_WIDTH-1:0] mem;
  logic [NUM_WORDS-1:0]                             v;
  logic [CVA6Cfg.NrCommitPorts-1:0][NUM_WORDS-1:0]         sel;
  logic [CVA6Cfg.NrCommitPorts-1:0][NUM_WORDS-1:0]         mask;
  logic [CVA6Cfg.NrCommitPorts-1:0][NUM_WORDS-1:0] we_dec;

  generate
    if (CVA6Cfg.CheriPresent) begin : gen_cheri_clear_caps
      genvar k;
      for (k = 0; k < CVA6Cfg.NrCommitPorts; k++) begin
        assign sel[k]  = (8'b11111111 << (quarter_i << 3));
        assign mask[k] = (mask_i << (quarter_i << 3));
      end
    end else begin
       assign sel = '0;
       assign mask = '0;
    end
  endgenerate

  always_comb begin : we_decoder
    for (int unsigned j = 0; j < CVA6Cfg.NrCommitPorts; j++) begin
      for (int unsigned i = 0; i < NUM_WORDS; i++) begin
        if (waddr_i[j] == i) we_dec[j][i] = we_i[j];
        else if (CVA6Cfg.CheriPresent && (clr_i[j] && sel[j][i])) we_dec[j][i] = we_i[j] & mask[j][i];
        else we_dec[j][i] = 1'b0;
      end
    end
  end

  // loop from 1 to NUM_WORDS-1 as R0 is nil
  always_ff @(posedge clk_i, negedge rst_ni) begin : register_write_behavioral
    if (~rst_ni) begin
      mem <= '{default: '0};
      v   <= '{default: '0};
    end else begin
      for (int unsigned j = 0; j < CVA6Cfg.NrCommitPorts; j++) begin
        for (int unsigned i = 0; i < NUM_WORDS; i++) begin
          if (we_dec[j][i]) begin
            mem[i] <= wdata_i[j];
            if (CVA6Cfg.CheriPresent) v[i] <= clr_i[j] ? 1'b0 : 1'b1;
          end
        end
        if (ZERO_REG_ZERO) begin
          mem[0] <= '0;
        end
      end
    end
  end

  for (genvar i = 0; i < NR_READ_PORTS; i++) begin : gen_read_register
    if (CVA6Cfg.CheriPresent) begin : gen_cheri_read_regs
      assign rdata_o[i] = !v[raddr_i[i]] ? '{default: '0} : mem[raddr_i[i]];
    end else begin : gen_no_cheri_read_regs
      assign rdata_o[i] = mem[raddr_i[i]];
    end
  end

endmodule

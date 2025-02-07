// Copyright 2025 Bruno Sá and Zero-Day Labs.
// Copyright and related rights are licensed under the Solderpad Hardware
// License, Version 0.51 (the "License"); you may not use this file except in
// compliance with the License.  You may obtain a copy of the License at
// http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
// or agreed to in writing, software, hardware and materials distributed under
// this License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
module cva6_cheri_tag_mem #(
  parameter TAG_MEM_SIZE = (2**25) / 16
) (
    input logic clk_i,
    input logic rst_ni,
    // TODO resize this to be the correct size
    input logic [63:0] address_i,
    input logic we_i,
    input logic writedata_i,
    output logic readdata_o
);

  /* verilator lint_off WIDTHCONCAT */
  logic [TAG_MEM_SIZE-1:0] tags;

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      tags <= '0;
    end else begin
      if (we_i && address_i < TAG_MEM_SIZE) begin
        tags[address_i] <= writedata_i;
      end else begin
        readdata_o <= address_i < TAG_MEM_SIZE ? tags[address_i] : '0;
      end
    end
  end
/* verilator lint_on WIDTHCONCAT */
endmodule
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
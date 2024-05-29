package dii_pkg;

  localparam NRET = 1;
  localparam ILEN = 32;

  typedef struct packed {
    logic [NRET-1:0]                 valid;
    logic [NRET*ILEN-1:0]            insn;
  } dii_instr_resp_t;

  typedef struct packed {
    logic [NRET-1:0]                 ready;
  } dii_instr_req_t;


endpackage
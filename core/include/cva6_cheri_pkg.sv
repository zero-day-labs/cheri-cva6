/* Copyright 2022 Bruno Sá and Zero-Day, Labs.
 * Copyright and related rights are licensed under the Solderpad Hardware
 * License, Version 0.51 (the “License”); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 * http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
 * or agreed to in writing, software, hardware and materials distributed under
 * this License is distributed on an “AS IS” BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * File:   cva6_cheri_pkg.sv
 * Author: Bruno Sá <bruno.vilaca.sa@gmail.com>
 * Date:   24.9.2022
 *
 * Description: Contains CHERI related structures and interfaces
 * Adapted from the CHERI Capability Library (https://github.com/CTSRD-CHERI/cheri-cap-lib)
 */


package cva6_cheri_pkg;

    /* CHERI Constants */
    localparam XLEN                 = cva6_config_pkg::CVA6ConfigXlen;
    localparam CLEN                 = 2*XLEN;                // Capability length two times the normal width
    localparam CTLEN                = 2*XLEN + 1;                // Capability + Tag bit
    localparam CAP_ADDR_WIDTH       = XLEN;                      // Capability address width
    localparam CAP_UPERMS_WIDTH     = (XLEN == 64) ? 4 : 0;      // Capability software permissions width
    localparam CAP_UPERMS_SHIFT     = (XLEN == 64) ? 15 : 0;
    localparam CAP_HPERMS_WIDTH     = 12;
    localparam CAP_FLAGS_WIDTH      = 1;
    localparam CAP_RSERV_WIDTH      = 2;                                // Capability reserved bits width
    localparam CAP_M_WIDTH          = (XLEN == 64) ? 14 : 8;
    localparam CAP_E_WIDTH          = 6;
    localparam CAP_E_HALF_WIDTH     = CAP_E_WIDTH/2;
    localparam CAP_OTYPE_WIDTH      = (XLEN == 64) ? 18 : 4;
    localparam CAP_RESET_EXP        = CAP_ADDR_WIDTH + 2 - CAP_M_WIDTH;
    localparam CAP_RESET_TOP        = {2'b01,{CAP_M_WIDTH-2{1'b0}}};
    localparam CAP_EXP_NUM          = 29;

    // -----
    // CSRs
    // -----
    typedef enum logic [4:0] {
        SCR_PCC         = 0,
        SCR_DDC         = 1,
        SCR_UTCC        = 4,
        SCR_UTDC        = 5,
        SCR_USCRATCHC   = 6,
        SCR_UEPCC       = 7,
        SCR_STCC        = 12,
        SCR_STDC        = 13,
        SCR_SSCRATCHC   = 14,
        SCR_SEPCC       = 15,
        SCR_VSTCC       = 20,
        SCR_VSTDC       = 21,
        SCR_VSSCRATCHC  = 22,
        SCR_VSEPCC      = 23,
        SCR_MTCC        = 28,
        SCR_MTDC        = 29,
        SCR_MSCRATCHC   = 30,
        SCR_MEPCC       = 31
    } scr_reg_t /*verilator public*/;

    // This functions converts S-mode SCR addresses into VS-mode SCR addresses
    // when V=1 (i.e., running in VS-mode).
    function automatic scr_reg_t convert_vs_access_scr(scr_reg_t scr_addr, logic v);
        scr_reg_t ret;
        ret = scr_addr;
        unique case (scr_addr) inside
        [SCR_STCC : SCR_SEPCC]: begin
          if (v) begin
            ret[4:3] = 2'b10;
          end
          return ret;
        end
        default: return ret;
        endcase
    endfunction

    /* Capabilities RISC-V Exception Trap Encoding Extension */

    localparam logic [XLEN-1:0] CAP_LOAD_PAGE_FAULT       = 26;
    localparam logic [XLEN-1:0] CAP_STORE_AMO_PAGE_FAULT  = 27;
    localparam logic [XLEN-1:0] CAP_EXCEPTION             = 28;

    /* Capabilities Exception Codes */

    localparam logic [4:0] CAP_LENGTH_VIOLATION            = 1;
    localparam logic [4:0] CAP_TAG_VIOLATION               = 2;
    localparam logic [4:0] CAP_SEAL_VIOLATION              = 3;
    localparam logic [4:0] CAP_TYPE_VIOLATION              = 4;
    localparam logic [4:0] CAP_USER_DEF_PERM_VIOLATION     = 8;
    localparam logic [4:0] CAP_REPRE_VIOLATION             = 10;
    localparam logic [4:0] CAP_UNLIGNED_BASE               = 11;
    localparam logic [4:0] CAP_GLOBAL_VIOLATION            = 16;
    localparam logic [4:0] CAP_PERM_EXEC_VIOLATION         = 17;
    localparam logic [4:0] CAP_PERM_LD_VIOLATION           = 18;
    localparam logic [4:0] CAP_PERM_ST_VIOLATION           = 19;
    localparam logic [4:0] CAP_PERM_LD_CAP_VIOLATION       = 20;
    localparam logic [4:0] CAP_PERM_ST_CAP_VIOLATION       = 21;
    localparam logic [4:0] CAP_PERM_ST_CAP_LOCAL_VIOLATION = 22;
    localparam logic [4:0] CAP_PERM_SEAL                   = 23;
    localparam logic [4:0] CAP_PERM_ACCESS_SYS_REGS        = 24;
    localparam logic [4:0] CAP_PERM_CINVOKE                = 25;
    localparam logic [4:0] CAP_PERM_ACCESS_CINVOKE_IDC     = 26;
    localparam logic [4:0] CAP_PERM_UNSEAL                 = 27;
    localparam logic [4:0] CAP_PERM_SET_CID                = 28;

    /* Capabilities OType Encoding */

    localparam logic [CAP_OTYPE_WIDTH-1:0] UNSEALED_CAP     = -1;
    localparam logic [CAP_OTYPE_WIDTH-1:0] SENTRY_CAP       = -2;
    localparam logic [CAP_OTYPE_WIDTH-1:0] MEM_TYPE_TOK_CAP = -3;
    localparam logic [CAP_OTYPE_WIDTH-1:0] IND_ENT_CAP      = -4;
    localparam logic [CAP_OTYPE_WIDTH-1:0] SEALED_CAP       = -17;
    localparam logic [CAP_OTYPE_WIDTH-1:0] OTYPE_MAX        = -5;

    /* Types definition */

    typedef logic                                             bool_t;
    typedef logic [CTLEN-1:0]                                 capw_t;
    typedef logic [CAP_ADDR_WIDTH-1:0]                        addrw_t;
    typedef logic [CAP_ADDR_WIDTH:0]                          addrwe_t;
    typedef logic [CAP_ADDR_WIDTH+1:0]                        addrwe2_t;
    typedef logic [CAP_ADDR_WIDTH - CAP_M_WIDTH -1:0]         addrmw_t;
    typedef logic [CAP_ADDR_WIDTH - (CAP_M_WIDTH - 1) :0]     addrmwm2_t;
    typedef logic [CAP_RSERV_WIDTH-1:0]                       resw_t;
    typedef logic [CAP_OTYPE_WIDTH-1:0]                       otypew_t;
    typedef logic [CAP_UPERMS_WIDTH-1:0]                      upermsw_t;
    typedef logic [CAP_M_WIDTH-1:0]                           mw_t;
    typedef logic [CAP_M_WIDTH:0]                             mwe_t;
    typedef logic [CAP_M_WIDTH+1:0]                           mwe2_t;
    typedef logic [CAP_M_WIDTH-3:0]                           cmw_t;
    typedef logic [((CAP_M_WIDTH-CAP_E_HALF_WIDTH)-1):0]      hmw_t;
    typedef logic [((CAP_M_WIDTH -(CAP_E_HALF_WIDTH+2))-1):0] hcmw_t;
    typedef logic [CAP_E_WIDTH-1:0]                           ew_t;
    typedef logic [CAP_E_HALF_WIDTH-1:0]                      hew_t;

    /**
      * Capability Control and Status Registers (CCSRs)
      */

    typedef struct packed {
        logic [63:16]   wiri2;
        logic [15:10]   cap_idx;
        logic [9:5]     cause;
        logic [4:2]     wiri1;
        bool_t          d;
        bool_t          e;
    } ccsr_t;

    /**
      * CHERI exception tval layout fields
      */
    typedef struct packed {
        logic [XLEN-1:11] wpri;
        logic [10:5]      cap_idx; /* index of the capability that causes the exception */
        logic [4:0]       cause;   /* CHERI exception code */
    } cap_tval_t;

    /**
      * Capability architectural defined permission bits
      */
    typedef struct packed {
        /**
          * Allow the architectural compartment ID to be set to this capability’s
          * base + offset using CSetCID.
          * NOT IMPLEMENTED FOR RISC-V
          */
        bool_t   permit_set_cid;
        /**
          * Allows access to privileged processor permitted by the architecture
          * (e.g., by virtue of being in supervisor mode), with architecture-specific
          * implications. This bit limits access to features such as MMU manipulation,
          * interrupt management, processor reset, and so on. The operating system
          * can remove this permission to implement constrained compartments within
          * the kernel.
          */
        bool_t   access_sys_regs;
        /**
          * Allow this capability to be used to unseal another capability with a
          * otype equal to this capability’s base + offset.
          */
        bool_t   permit_unseal;
        /// Allow this sealed capability to be used with CInvoke.
        bool_t   permit_cinvoke;
        /**
          * Allow this capability to authorize the sealing of another capability
          * with a otype equal to this capability’s base + offset.
          */
        bool_t   permit_seal;
        /// Allow this capability to be used to store non-global capabilities.
        bool_t   permit_store_local_cap;
        /// Allow this capability to be used to store capabilities with valid tags.
        bool_t   permit_store_cap;
        /// Allow this capability to be used to load capabilities with valid tags.
        bool_t   permit_load_cap;
        /// Allow this capability to be used to store untagged data
        bool_t   permit_store;
        /// Allow this capability to be used to load untagged data.
        bool_t   permit_load;
        /**
          * Allow this capability to be used in the PCC register as a capability
          * for the program counter, constraining control flow.
          */
        bool_t   permit_execute;
        /**
          * Allow this capability to be stored via capabilities that do not
          * themselves have PERMIT_STORE_LOCAL_CAPABILITY set.
          */
        bool_t   gbl;
    } cap_hperms_t;

    /* Capability flags definition */
    typedef struct packed {
        /**
          * RISC-V Encoding mode for PCC
          * 0 - Conventional RISC-V execution mode, in which address operands
          *     to existing RISC-V load and store opcodes contain integer addresses.
          * 1 - CHERI capability encoding mode, in which address operands
          *     to existing RISC-V load and store opcodes contain capabilities.
          */
        bool_t   cap_mode;
    } cap_flags_t;

    /* Capability bounds definition */
    typedef struct packed {
        ew_t  exp;
        mw_t  top_bits;
        mw_t  base_bits;
    } cap_bounds_t;

    /* Capability format definition */
    typedef enum logic {
        EXP0,
        EMBEDDED_EXP
    } cap_fmt_t /*verilator public*/;

    /* Capability format EXP0 definition */
    typedef struct packed {
        cmw_t top;
        mw_t  base;
    } cap_exp0_fmt_t;

    /* Capability format EMBEDDED_EXP definition */
    typedef struct packed {
        hcmw_t top_bits;
        hew_t  exp_top_bits;
        hmw_t  base_bits;
        hew_t  exp_base_bits;
    } cap_embedded_exp_fmt_t;

    /* Capability memory compressed bounds definition */

    typedef union packed {
        struct packed {
            cmw_t  top_bits;
            mw_t   base_bits;
        } cbounds;
        cap_exp0_fmt_t exp0_fmt;
        cap_embedded_exp_fmt_t exp_fmt;
    } cap_cbounds_t;

    /* Capability decoding meta fields */
    typedef struct packed {
        logic [2:0] r;
        bool_t      top_hi_r;
        bool_t      base_hi_r;
        bool_t      addr_hi_r;
        logic [1:0] ct;
        logic [1:0] cb;
    } cap_meta_data_t;

    /* Capability definition in memory */
    typedef struct packed {
        bool_t                          tag;
        upermsw_t                       uperms;
        cap_hperms_t                    hperms;
        resw_t                          res;
        cap_flags_t                     flags;
        otypew_t                        otype;
        cap_fmt_t                       int_e;
        cap_cbounds_t                   bounds;
        addrw_t                         addr;
    } cap_mem_t;

    /* Capability definition in register */
    typedef struct packed {
        bool_t                          tag;
        mw_t                            addr_mid;
        upermsw_t                       uperms;
        cap_hperms_t                    hperms;
        cap_flags_t                     flags;
        resw_t                          res;
        otypew_t                        otype;
        cap_fmt_t                       int_e;
        cap_bounds_t                    bounds;
        addrw_t                         addr;
    } cap_reg_t;

    /* Full PCC Capability definition */
    typedef struct packed {
        bool_t                          tag;
        upermsw_t                       uperms;
        cap_hperms_t                    hperms;
        cap_flags_t                     flags;
        resw_t                          res;
        otypew_t                        otype;
        cap_fmt_t                       int_e;
        ew_t                            exp;
        addrw_t                         base;
        addrwe_t                        top;
        mw_t                            addr_mid;
        addrw_t                         addr;
    } cap_pcc_t;


    /* Capability set bounds return */
    typedef struct packed {
        cap_reg_t   cap;
        bool_t      exact;
        addrwe_t    length;
        addrw_t     mask;
    } cap_reg_set_bounds_ret_t;

    /* Capability default values for bounds and compressed bounds */
    localparam cap_bounds_t DEFAULT_BOUNDS_CAP = '{
        exp          : CAP_RESET_EXP,
        top_bits     : CAP_RESET_TOP,
        base_bits    : '{default: 0}
    };
    localparam cap_cbounds_t DEFAULT_CBOUNDS_CAP = '0;
    /* Capability default root capability and null capabilities for PCC and capability registers */
    localparam cap_reg_t REG_ROOT_CAP = '{
        tag             : 1'b1,
        addr            : '{default: 0},
        addr_mid        : '{default: 0},
        uperms          : '{default: '1},
        hperms          : '{default: '1},
        flags           : 1'b0,
        res             : '0,
        otype           : UNSEALED_CAP,
        int_e           : EMBEDDED_EXP,
        bounds          : DEFAULT_BOUNDS_CAP
    };

    localparam cap_reg_t REG_NULL_CAP = '{
        tag             : 1'b0,
        addr            : '{default: 0},
        addr_mid        : '{default: 0},
        uperms          : '{default: 0},
        hperms          : '{default: 0},
        flags           : 1'b0,
        res             : '0,
        otype           : UNSEALED_CAP,
        int_e           : EMBEDDED_EXP,
        bounds          : DEFAULT_BOUNDS_CAP
    };

    localparam cap_pcc_t PCC_ROOT_CAP = '{
        tag             : 1'b1,
        res             : '0,
        addr            : '{default: 0},
        addr_mid        : '{default: 0},
        base            : '{default: 0},
        top             : (1 << 64),
        uperms          : '{default: '1},
        hperms          : '{default: '1},
        flags           : 1'b0,
        otype           : UNSEALED_CAP,
        exp             : 52,
        int_e           : EMBEDDED_EXP
    };

    localparam cap_pcc_t PCC_NULL_CAP = '{
        tag             : 1'b0,
        res             : '0,
        uperms          : '{default: 0},
        hperms          : '{default: 0},
        flags           : 1'b0,
        otype           : UNSEALED_CAP,
        int_e           : EMBEDDED_EXP,
        exp             : 52,
        base            : '{default: 0},
        top             : (1 << 64),
        addr            : '{default: 0},
        addr_mid        : '{default: 0}
    };

    localparam cap_mem_t MEM_NULL_CAP = '{
        tag             : 1'b0,
        uperms          : '{default: 0},
        hperms          : '{default: 0},
        res             : '0,
        flags           : 1'b0,
        otype           : UNSEALED_CAP,
        int_e           : EMBEDDED_EXP,
        bounds          : encode_bounds(DEFAULT_BOUNDS_CAP, EMBEDDED_EXP),
        addr            : '{default: 0}
    };

    /* Capability memory interface */

    function automatic bool_t is_cap_mem_valid(capw_t cap);
        cap_mem_t ret = cap_mem_t'(cap);
        return ret.tag;
    endfunction

    function automatic capw_t set_cap_mem_valid(capw_t cap, bool_t tag);
        cap_mem_t ret = cap;
        ret.tag = tag;
        return ret;
    endfunction

    function automatic cap_flags_t get_cap_mem_flags(capw_t cap);
        cap_mem_t ret = cap;
        return ret.flags;
    endfunction

    function automatic capw_t set_cap_mem_flags(capw_t cap,cap_flags_t flags);
        cap_mem_t ret = cap;
        ret.flags = flags;
        return ret;
    endfunction

    function automatic cap_hperms_t get_cap_mem_reg_hperms (capw_t cap);
        cap_mem_t ret = cap;
        return ret.hperms;
    endfunction

    function automatic addrw_t get_cap_mem_addr (capw_t cap);
        cap_mem_t ret = cap;
        return ret.addr;
    endfunction

   function automatic addrw_t set_cap_mem_addr_unsafe (capw_t cap, addrw_t addr);
        cap_mem_t ret = cap;
        ret.addr = addr;
        return ret.addr;
    endfunction

    function automatic addrw_t set_cap_mem_addr_inc (capw_t cap, addrw_t inc);
        cap_mem_t ret = cap;
        addrw_t addr = get_cap_mem_addr(cap);
        ret.addr = set_cap_mem_addr_unsafe(cap, addr + $signed(inc));
        return ret.addr;
    endfunction
    /**
     * Capability Register Interface
     */

    /**
     * @brief Function that sets the PCC capability cursor or address.
     * @param cap capability in register format.
     * @param cursor a [63:0] value with the cursor to be set.
     * @returns capability PCC with addr set to input address.
     */
    function automatic cap_pcc_t set_cap_pcc_cursor (cap_pcc_t cap, addrw_t cursor);
        cap_pcc_t ret = cap;
        ret.addr      = cursor;
        ret.addr_mid  = ret.addr >> cap.exp;
        return ret;
    endfunction

    /**
     * Capability Register Interface
     */

    /**
     * @brief Function check if capability valid.
     * @param cap capability in register format.
     * @returns 1 if capability is valid and 0 otherwise.
     */
    function automatic bool_t is_cap_reg_valid (cap_reg_t cap);
        return cap.tag;
    endfunction

    /**
     * @brief Function set capability tag bit.
     * @param cap capability in register format.
     * @param tag bool type bit to set the capability tag.
     * @returns capability cap with valid bit set to the input tag.
     */
    function automatic cap_reg_t set_cap_reg_valid (cap_reg_t cap, bool_t tag);
        cap_reg_t ret = cap;
        ret.tag = tag;
        return ret;
    endfunction

    /**
     * @brief Function checks if the object type is a reserved type .
     * @param otype object type.
     * @returns capability 1 if the otypes is a reserved type.
     */
    function automatic bool_t is_cap_type_reserv (otypew_t otype);
        addrw_t type_unsigned       = otype;
        addrw_t otype_max_unsigned  = $signed(OTYPE_MAX);
        return type_unsigned > otype_max_unsigned;
    endfunction

    /* function automatic bool_t is_cap_reg_derivable (cap_reg_t cap);
        bool_t derivable = ( cap.bounds.exp <= CAP_RESET_EXP &&
            !(cap.bounds.exp == CAP_RESET_EXP && ((cap.bounds.top_bits[CAP_M_WIDTH-1] != 1'b0) ||
                                     (cap.bounds.base_bits[CAP_M_WIDTH-1:CAP_M_WIDTH-2] != 2'b0))) &&
            !(cap.bounds.exp == CAP_RESET_EXP-1 && (cap.bounds.base_bits[CAP_M_WIDTH-1] != 1'b0)) &&
            (cap.res == 0));
        return derivable;
    endfunction */


    function automatic cap_reg_t seal(cap_reg_t cap, otypew_t otype);
        cap_reg_t ret = cap;
        // Update the fields of the new sealed capability (otype)
        ret.otype = otype;
        return ret;
    endfunction

    /**
     * @brief Function to unseal the input capabilitu.
     * @param cap capability in register format.
     * @returns capability cap with otype field set to UNSEALED_CAP.
     */
    function automatic cap_reg_t unseal(cap_reg_t cap);
        cap_reg_t ret = cap;
        ret.otype = UNSEALED_CAP;
        return ret;
    endfunction

    /**
     * @brief Function to get the capability meta data using CHERI concentrate 128-bit decoding.
     * @param cap capability in register format.
     * @returns the capability meta data top and base corrections (ct and cb)
     *          , comparison values of A3 < R, T3 < R and B3 < R and the value
     *          of the representable region R.
     */
    function automatic cap_meta_data_t get_cap_reg_meta_data (cap_reg_t cap);

        cap_meta_data_t ret_info;
        ew_t exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;
        logic [2:0] t = cap.bounds.top_bits[CAP_M_WIDTH-1:CAP_M_WIDTH-3];
        logic [2:0] b = cap.bounds.base_bits[CAP_M_WIDTH-1:CAP_M_WIDTH-3];
        logic [2:0] a = cap.addr >> (exp + CAP_M_WIDTH-3);
        logic [2:0] r = b - 3'b001;
        logic top_hi_r  = t < r;
        logic base_hi_r = b < r;
        logic addr_hi_r = a < r;
        logic [1:0] ct  = (top_hi_r  ==  addr_hi_r) ? 0 :
                            (top_hi_r  && !addr_hi_r) ? 1 :
                                                        -1;
        logic [1:0] cb  = (base_hi_r ==  addr_hi_r) ? 0 :
                               (base_hi_r && !addr_hi_r) ? 1 :
                                                           -1;
        ret_info = '{
            r         : r,
            top_hi_r  : top_hi_r,
            base_hi_r : base_hi_r,
            addr_hi_r : addr_hi_r,
            ct        : ct,
            cb        : cb
        };
      return ret_info;
    endfunction

    /**
     * @brief Function to compute the capability base address.
     * @param cap capability in register format.
     * @returns the base address with size [CAP_ADDR_WIDTH-1:0].
     */
    function automatic addrw_t get_cap_reg_base(cap_reg_t cap, cap_meta_data_t cap_meta_data);
        addrw_t msk_top_bits; /**< mask to fetch address top bits [XLEN:E+14] */
        addrw_t offset_base; /**< base offset value to be sum */
        ew_t exp;

        exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;

        msk_top_bits = (-1 << (exp + CAP_M_WIDTH));
        // offset_base = base correction coeficient (cb) + base_bits
        offset_base  = $signed({cap_meta_data.cb, cap.bounds.base_bits}) << exp;
        // return base address = address top [XLEN:E+14] bits + base address offset
        // base[E-1:0] = 0'E
        return ((cap.addr & msk_top_bits) + offset_base);
    endfunction

    /**
     * @brief Function to compute the capability top address.
     * @param cap capability in register format.
     * @returns the top address with size [CAP_ADDR_WIDTH:0].
     */
    function automatic addrwe_t get_cap_reg_top(cap_reg_t cap, cap_meta_data_t cap_meta_data);
        addrwe_t msk_top_bits; /**< mask to fetch address top bits [XLEN:E+14] */
        addrwe_t offset_base; /**< top and base offset value */
        addrwe_t ret, offset_top; /**< address to return */
        logic [1:0] top_msb, base_msb; /**< top and base address MSB bits [63:64]*/
        ew_t exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;

        msk_top_bits = (-1 << (exp + CAP_M_WIDTH));
        // offset_top = top correction coeficient (ct) + top_bits
        offset_top  = $signed({cap_meta_data.ct, cap.bounds.top_bits}) << exp;
        // returntop address = address top [XLEN:E+14] bits + top address offset
        // top[E-1:0] = 0'E
        ret = (({1'b0,cap.addr} & msk_top_bits) + offset_top);

        /**
         * Corner case check to allow the entire 64-bit address space to addressable
         * the top address is permit to be a 65-bit value. Additional check is required
         * to correct the top base address:
         * if ((E < 51) &((t[64 : 63] − b[63]) > 1)) then t[64] =!t[64]
         */

        top_msb = ret[CAP_ADDR_WIDTH:CAP_ADDR_WIDTH-1];
        offset_base = $signed({cap_meta_data.cb, cap.bounds.base_bits});
        offset_base = offset_base << exp;
        offset_base = ({1'b0,cap.addr} & msk_top_bits) + offset_base;
        //offset_base = ({1'b0,cap.addr} & msk_top_bits) + ($signed({cap_meta_data.cb, cap.bounds.base_bits}) << cap.bounds.exp);
        base_msb = {1'b0, offset_base[CAP_ADDR_WIDTH-1]};
        if (exp == (CAP_RESET_EXP - 1)) base_msb = {1'b0, cap.bounds.base_bits[CAP_M_WIDTH-1]};
        if ((exp < (CAP_RESET_EXP-1)) && ((top_msb - base_msb) > 1))
            ret[CAP_ADDR_WIDTH] = ~ret[CAP_ADDR_WIDTH];
        // if E >= 52, length takes up the entire address space
        return /* (cap.bounds.exp >= CAP_RESET_EXP) ? 1 << XLEN : */ ret;
    endfunction

    /**
     * @brief Function to compute the capability length address.
     * @param cap capability in register format.
     * @param dec_bounds decounds bounds meta data.
     * @returns the capability length with size [CAP_ADDR_WIDTH:0].
     */
    function automatic addrwe_t get_cap_reg_length(cap_reg_t cap, cap_meta_data_t cap_meta_data);
        /**< compute top and base mid bits [E+13:E] */
        logic [CAP_M_WIDTH + 1 : 0] top_mid_bits, base_mid_bits;
        logic [CAP_M_WIDTH + 1 : 0] length_mid_bits;
        /**< length [CAP_ADDR_WIDTH:0] plus 1 bit to accomodate the entire address space */
        logic [CAP_ADDR_WIDTH:0] length;
        top_mid_bits = {cap_meta_data.ct, cap.bounds.top_bits};
        base_mid_bits = {cap_meta_data.cb, cap.bounds.base_bits};
        length_mid_bits = top_mid_bits - base_mid_bits;
        length = $unsigned(length_mid_bits) << cap.bounds.exp;
        // if E >= 52, length takes up the entire address space
        return /* (cap.bounds.exp >= CAP_RESET_EXP) ? ~(1 << XLEN) : */ length;
    endfunction

    /**
     * @brief Function to compute the capability offset address.
     * @param cap capability in register format.
     * @param dec_bounds decounds bounds meta data.
     * @returns the capability offset with size [CAP_ADDR_WIDTH-1:0].
     */
    function automatic addrw_t get_cap_reg_offset(cap_reg_t cap, cap_meta_data_t cap_meta_data);
        /**< compute base and address mid bits [E+13:E] */
        mwe2_t base_offset;
        /**< offset = address - base */
        mw_t addr_offset;
        addrw_t msk_lsb_addr, offset_lsb, offset;
        ew_t exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;

        base_offset = $signed({cap_meta_data.cb, cap.bounds.base_bits});
        //addr_offset = cap.addr >> cap.bounds.exp;
        addr_offset = cap.addr_mid;
        offset = $signed({2'b0,addr_offset} - base_offset) << exp;
        msk_lsb_addr = ~(-1 << exp);
        offset_lsb = cap.addr & msk_lsb_addr;

        return $signed( offset | offset_lsb);
    endfunction

    /**
     * @brief Function sets the capability address and check if is representable.
     * @param cap capability in register format.
     * @param cursor target address for the resulting capability.
     * @param cap_meta_data capability decounds bounds meta data.
     * @returns the input capability with address set to cursor and clear the tag
     *          if the capability is not representable.
     */
    function automatic cap_reg_t set_cap_reg_address(cap_reg_t cap, addrw_t address, cap_meta_data_t cap_meta_data);
        cap_reg_t ret = cap;
        ew_t exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;
        addrw_t addr_mid = $unsigned(address >> exp);
        // compute new
        logic newAddrHi  = addr_mid[CAP_M_WIDTH-1:CAP_M_WIDTH-3] < cap_meta_data.r;
        addrw_t deltaAddrHi = $signed({1'b0,newAddrHi} - {1'b0,cap_meta_data.addr_hi_r}) << (cap.bounds.exp + CAP_M_WIDTH);
        // Calculate the actual difference between the upper bits of the new address and the original address.
        addrw_t mask = -1 << (exp + CAP_M_WIDTH);
        addrw_t deltaAddrUpper = (address & mask) - (cap.addr & mask);
        logic is_rep = deltaAddrHi == deltaAddrUpper;
        ret.addr = address;
        ret.addr_mid = address >> exp;
        if (!(is_rep)) ret.tag = 1'b0;
        return ret;
    endfunction

    /**
     * @brief Function sets the capability address without representable checking.
     * @param cap capability in register format.
     * @param cursor target address for the resulting capability.
     * @returns the input capability with address set to cursor
     */
    function automatic cap_reg_t set_cap_reg_addr(cap_reg_t cap, addrw_t address);
        cap_reg_t ret = cap;
        ew_t exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;
        ret.addr = address;
        ret.addr_mid = address >> exp;
        return ret;
    endfunction

    /**
     * @brief Function to compute the capability offset address.
     * @param cap capability in register format.
     * @param cursor target address for the resulting capability.
     * @param offset holds the capability offset when set_offset = 1
     *               and the increment offset when set_offset = 0.
     * @param cap_meta_data capability decounds bounds meta data.
     * @param set_offset 0 - the function sets the capability offset to the input offset.
     *                   1 - the functions set the capability offset to cap.offset + offset.
     * @returns the capability offset with size [CAP_ADDR_WIDTH-1:0].
     */
    function automatic cap_reg_t cap_reg_inc_offset(cap_reg_t cap
                                  , addrw_t cursor
                                  , addrw_t offset // this is the increment in inc offset, and the offset in set offset
                                  , cap_meta_data_t cap_meta_data
                                  , bool_t set_offset);
        cap_reg_t ret = cap;
        // ----------------
        // In Range test
        // Description: Test of the offset increment is less that the representable region's
        // size s, i.e., -s < offset < s. This test is reduce to test that all bits of the
        // offset top (offset[63:E+14]) are all the same.
        // ----------------

        addrw_t msk_offset_msb = -1 << (cap.bounds.exp + CAP_M_WIDTH);
        addrw_t sign = $signed(offset[CAP_ADDR_WIDTH-1]);
        addrw_t offset_msb_bits = offset;
        logic in_range = (((offset_msb_bits ^ sign) & msk_offset_msb) == 0);
        ew_t exp = (cap.bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : cap.bounds.exp;

        // ----------------
        // In Limit Test
        // Description: Checks if the update on the Amid ([E+14:E]) could take the address
        // beyond the representable limits. It compares the distance from the offset middle
        // bits [E+14:E] ti the edges of the representable space in the middle bits.
        // Algorithm as follow:
        // - offset >= 0 (positive increment)
        //   in_limit = offset[E+14:E] < (R - cap.addr[E+14:E] -1)
        // - offset < 0 (negative increment)
        //   in_limit =  (offset[E+14:E]>= (R - cap.addr[E+14:E]) and R != cap.addr[E+14:E]
        // (i.e., we are not on the bottom of edge of the representable space).

        // Increment sign:
        // 1 -> negative increment
        // 0 -> positive increment
        logic inc_sign = offset[CAP_ADDR_WIDTH-1];

        // Get offset middle bits [E+14:E]
        mw_t offset_mid  = offset >> (exp);

        // Compute distance to representable bounds when set_offset == true
        // We will denominate this distance as to_rep_bounds1

        // Amid = B (base bits)
        mw_t to_rep_bounds1_0 = {3'b111,11'b00000000000} - {3'b000,cap.bounds.base_bits[CAP_M_WIDTH-4:0]};
        // equivalent to (repBoundBits - cap.bounds.baseBits - 1):
        mw_t to_rep_bounds1_1 = {3'b110,~cap.bounds.base_bits[CAP_M_WIDTH-4:0]};

        // Compute distance to representable bounds when set_offset == false
        // We will denominate this distance as to_rep_bounds2
        // r = representable bounds
        mw_t R = {cap_meta_data.r,11'b00000000000};
        //mw_t addr_mid = cap.addr >>  (cap.bounds.exp + CAP_M_WIDTH);
        mw_t addr_mid = cap.addr_mid;
        mw_t to_rep_bounds2_0 = R - addr_mid;
        // to compute rep_bounds2_1 we use the complement for 2 representation
        mw_t to_rep_bounds2_1 = R + ~addr_mid;
        // select distance to bounds
        mw_t dist_to_bounds0 = set_offset ? to_rep_bounds1_0 : to_rep_bounds2_0;
        mw_t dist_to_bounds1 = set_offset ? to_rep_bounds1_1 : to_rep_bounds2_1;
        // Check if addr is not already at the bottom of the representable edge
        logic is_addr_at_rep_bot_edge = (R == addr_mid) && (set_offset == 1'b0);

        logic in_limits = 1'b0;
        logic in_bounds = 1'b0;

        // In limit test
        if (inc_sign) begin
          // negative increment
          in_limits = (offset_mid >= dist_to_bounds0) && !is_addr_at_rep_bot_edge;
        end else begin
          in_limits = set_offset ? offset_mid <= dist_to_bounds1
                               : offset_mid <  dist_to_bounds1;
        end

        // Complete representable bounds check
        // -----------------------------------
        in_bounds = (in_range && in_limits) || (exp >= (CAP_RESET_EXP - 2));
        // Update return capability
        ret.addr = cursor;
        ret.addr_mid = cursor >> exp;
        // if not in representable bounds nullify the capability
        if (!in_bounds)
            ret.tag = 1'b0;
        return ret;
    endfunction

    /**
     * @brief Function to check if capabiliy is within bounds.
     * @param cap capability in register format.
     * @param cap_meta_data capability decounds bounds meta data.
     * @param inclusive 0 - includes top in the in bounds check.
     *                  1 - excludes top in the inbounds check.
     * @returns 0 if not in bounds and 1 if in bounds.
     */
    function automatic bool_t is_cap_reg_inbounds(cap_reg_t cap, cap_meta_data_t meta_data, bool_t inclusive);
        mw_t addr_mid = cap.addr_mid;
        bool_t check_addr = inclusive ? addr_mid <= cap.bounds.top_bits
                            : addr_mid <  cap.bounds.top_bits;
        bool_t check_top  = (meta_data.addr_hi_r  == meta_data.addr_hi_r) ? check_addr : meta_data.addr_hi_r;
        bool_t check_base = (meta_data.base_hi_r  == meta_data.addr_hi_r) ? addr_mid >= cap.bounds.base_bits
                                         : meta_data.addr_hi_r;
        return check_top && check_base;
    endfunction

    /**
     * @brief Function to compute the in limit check
     * @param offset capability offset.
     * @param exp capability E.
     * @returns 0 - if not in limit and 1 - if in limit
     */
    function automatic bool_t is_offset_in_range(addrw_t offset, ew_t exp);
        bool_t ret;
        addrw_t offset_msb;
        logic cmp_top;

        offset_msb = $signed(offset >> (exp + CAP_M_WIDTH));
        cmp_top = |offset_msb;
        if (cmp_top == 0)
            ret = 1'b1;
        ret = 1'b0;
        return ret;
    endfunction

    /**
     * @brief Function to set the capability bounds
     * @param cap capability in register format.
     * @param base capability base address to be set.
     * @param lengthfull length of the capability to be set
     *                   top = base + length
     * @returns the capability with bounds set to base and length,
     *          a bool stating if the capability was exact aligned a 2*E+3,
     *          representable length and mask of the capability.
     */
    function automatic cap_reg_set_bounds_ret_t set_cap_reg_bounds (cap_reg_t cap, addrw_t base, addrwe_t lengthfull);
        cap_reg_set_bounds_ret_t ret = '{
            cap     : cap,
            exact   : 1'b0,
            length  : lengthfull,
            mask    : '0
        };
        addrwe_t length = lengthfull;
        // Compute initial E
        // E = 52 - CountingLeadingZeros(l[64:13]) in which l = length
        addrmwm2_t lengh_msb_bits = length[CAP_ADDR_WIDTH:CAP_M_WIDTH-1];
        ew_t cnt_zeros = $unsigned(count_zeros_msb(lengh_msb_bits));
        ew_t exp = CAP_RESET_EXP - cnt_zeros;
        // Compute Ie
        // - 0, if E=0 and l[12]=0
        // - 1, otherwise
        bool_t int_e = !(cnt_zeros == (CAP_RESET_EXP) && length[CAP_M_WIDTH-2] == 1'b0);
        // Compute new base and top middle bits [E+MW:E]
        addrwe2_t new_base = {2'b00, base};
        mwe2_t new_base_bits = new_base >> exp;
        addrwe2_t new_len = {1'b0, length};
        addrwe2_t new_top = new_base + new_len;
        mwe2_t new_top_bits = new_top >> exp;
        // Creates mask to check all bits bellow msb(l) = exp + CAP_MW_WIDTH;
        addrwe2_t lmsk_exp_bits = ~(-1 << (exp + 3));
        addrwe2_t lmsk_m_bits = ~(-1 << (exp + 3 + CAP_M_WIDTH - 4)) & ~lmsk_exp_bits;
        //addrwe2_t lmsk_m_less_1_bits = ~(-1 << (exp + 3 + CAP_M_WIDTH - 3)) & ~lmsk_exp_bits;
        addrwe2_t lmsk_m_less_1_bits = (-1 << (exp + 4)) & lmsk_m_bits;
        // Check if any of the lsb of len, base and top were lost, i.e., [Einitial+2:0]
        // are all non-zero
        bool_t lost_lsb_len = (new_len & lmsk_exp_bits) != 0 && int_e;
        bool_t lost_lsb_base = (new_base & lmsk_exp_bits) != 0 && int_e;
        bool_t lost_lsb_top = (new_top & lmsk_exp_bits) != 0 && int_e;
        bool_t is_exact = !(lost_lsb_base || lost_lsb_top);
        // Check if all mantissa bits above the Einitial+3 are all ones (i.e., length is max)
        bool_t is_len_max = (new_len & (lmsk_m_bits)) == (lmsk_m_bits);
        bool_t is_len_max_less_one = (new_len & (lmsk_m_bits)) == (lmsk_m_less_1_bits);
        // Check if we lost T[2:0] bits when int e = 1
        bool_t round_up_length = lost_lsb_top;
        // Check if there was a carry in from summing base[E+2,E] with len[E+2:E]
        addrwe2_t lmsk_carry_in_bit = (~(-1 << (exp + 4))) ^ lmsk_exp_bits;
        bool_t len_carry_in = (lmsk_carry_in_bit & new_top) != ((lmsk_carry_in_bit & new_base)^(lmsk_carry_in_bit & new_len));
        // Compute new values for top and base when we need to increase E
        mw_t new_top_bits_over = new_top_bits >> 1;
        mw_t new_base_bits_over = new_base_bits >> 1;
        // Check for length overflows
        bool_t length_over = 1'b0;
        //addrwe_t new_length_over = {2'b00, new_len};
        addrwe2_t new_length_over = new_len;
        addrw_t len_msk = -1;
        if (is_len_max && (len_carry_in || round_up_length)) length_over = 1'b1;
        if (is_len_max_less_one && len_carry_in && round_up_length) length_over = 1'b1;
        if(length_over && int_e) begin
            // C = , we need to increase the E
            exp = exp + 1;
            // Sum one to T if there was a overflow and we lost the 3 lsb bits of T
            ret.cap.bounds.top_bits = lost_lsb_top ? new_top_bits_over + 14'b00000000001000
                                                  : new_top_bits_over;
            ret.cap.bounds.base_bits = new_base_bits_over;
        end else begin
            ret.cap.bounds.top_bits = lost_lsb_top ? (new_top_bits[CAP_M_WIDTH-1:0] + 14'b00000000001000)
                                            : new_top_bits[CAP_M_WIDTH-1:0];
            ret.cap.bounds.base_bits = new_base_bits[CAP_M_WIDTH-1:0];
        end
        ret.cap.bounds.exp = exp;
        ret.cap.int_e = int_e ? EMBEDDED_EXP : EXP0;
        // Update bounds when E > 0, make 3 lsb bits 0
        if (int_e) begin
            ret.cap.bounds.top_bits = {ret.cap.bounds.top_bits[CAP_M_WIDTH-1:CAP_E_HALF_WIDTH], 3'b000};
            ret.cap.bounds.base_bits = {ret.cap.bounds.base_bits[CAP_M_WIDTH-1:CAP_E_HALF_WIDTH], 3'b000};
        end
        // Calculate the new representable length
        if (int_e) begin
            new_length_over = new_len + lmsk_carry_in_bit;
            new_len        = (new_len & (~lmsk_exp_bits));
            new_length_over = (new_length_over & (~lmsk_exp_bits));
            if (lost_lsb_len) new_len = new_length_over;
            len_msk = (is_len_max && lost_lsb_top) ?  (-1 << (exp + 3)) : ~lmsk_exp_bits[CAP_ADDR_WIDTH-1:0];
        end
        ret.cap.addr_mid  = cap.addr >> exp;
        // Return derived capability
        ret.exact = is_exact;
        ret.length = new_len[CAP_ADDR_WIDTH:0];
        ret.mask = len_msk;
        return ret;
    endfunction

    /**
     * @brief Function to set the capability object type to a arbitrary value.
     * @param cap capability in register format.
     * @param otype target object type for the capability.
     * @returns the input capability cap with otype field equal to the input otype.
     */
    function automatic cap_reg_t set_cap_reg_otype (cap_reg_t cap, otypew_t otype);
        cap_reg_t ret = cap;
        ret.otype = otype;
        return ret;
    endfunction

    /**
     * Capability formats conversion functions
     */

    /**
     * @brief Function to compute the capability offset address.
     * @param cap capability in register format.
     * @param dec_bounds decounds bounds meta data.
     * @returns the capability offset with size [CAP_ADDR_WIDTH-1:0].
     */
    function automatic capw_t cap_reg_to_cap_mem (cap_reg_t cap);
        cap_mem_t cap_mem = '{
            tag:       cap.tag,
            uperms:    cap.uperms,
            hperms:    cap.hperms,
            res:       cap.res,
            flags:     cap.flags,
            otype:     cap.otype,
            int_e:     cap.int_e,
            bounds:    encode_bounds(cap.bounds, cap.int_e),
            addr:      cap.addr
        };
        return capw_t'(cap_mem);
    endfunction

    /**
     * @brief Function to compute the capability offset address.
     * @param cap capability in register format.
     * @param dec_bounds decounds bounds meta data.
     * @returns the capability offset with size [CAP_ADDR_WIDTH-1:0].
     */
    function automatic cap_reg_t cap_mem_to_cap_reg (cap_mem_t cap);
        cap_reg_t ret;
        cap_bounds_t bounds = decode_bounds(cap.bounds, cap.int_e);
        ew_t exp = (bounds.exp > CAP_RESET_EXP) ? CAP_RESET_EXP : bounds.exp;
        ret = '{
            tag:       cap.tag,
            uperms:    cap.uperms,
            hperms:    cap.hperms,
            flags:     cap.flags,
            res:       cap.res,
            otype:     cap.otype,
            int_e:     cap.int_e,
            bounds:    bounds,
            addr:      cap.addr,
            addr_mid:  cap.addr >> exp
        };
        return ret;
    endfunction

    function automatic cap_pcc_t cap_reg_to_cap_pcc(cap_reg_t cap);
        cap_pcc_t cap_pcc;
        cap_meta_data_t cap_meta_data = get_cap_reg_meta_data(cap);
        cap_pcc.tag       = cap.tag;
        cap_pcc.uperms    = cap.uperms;
        cap_pcc.hperms    = cap.hperms;
        cap_pcc.flags     = cap.flags;
        cap_pcc.res       = cap.res;
        cap_pcc.otype     = cap.otype;
        cap_pcc.int_e     = cap.int_e;
        cap_pcc.exp       = cap.bounds.exp;
        cap_pcc.base      = get_cap_reg_base(cap,cap_meta_data);
        cap_pcc.top       = get_cap_reg_top(cap,cap_meta_data);
        cap_pcc.addr      = cap.addr;
        cap_pcc.addr_mid  = cap.addr >> cap.bounds.exp;
        return cap_pcc;
    endfunction

    function automatic cap_reg_t cap_pcc_to_cap_reg(cap_pcc_t cap);
        cap_reg_t cap_reg;
        addrw_t base = cap.base >> cap.exp;
        addrwe_t top = cap.top >> cap.exp;
        cap_reg.tag              = cap.tag;
        cap_reg.uperms           = cap.uperms;
        cap_reg.hperms           = cap.hperms;
        cap_reg.flags            = cap.flags;
        cap_reg.res              = cap.res;
        cap_reg.otype            = cap.otype;
        cap_reg.int_e            = cap.int_e;
        cap_reg.bounds.exp       = cap.exp;
        cap_reg.bounds.top_bits  = top[CAP_M_WIDTH-1:0];
        cap_reg.bounds.base_bits = base[CAP_M_WIDTH-1:0];
        cap_reg.addr_mid         = cap.addr_mid;
        cap_reg.addr             = cap.addr;
        return cap_reg;
    endfunction


    /**
      * Capability Auxiliary functions
      */

    /**
     * @brief Function that creates a mask from the msb set to 1 till 0
     * @param x value to extract mask from.
     * @returns a mask with all 1 from the msb bit set to 1 till 0.
     */
    function automatic addrwe2_t smearMSBRight(addrwe2_t x);
        addrwe2_t res = x;
        for (int i = 0; i < $clog2(CAP_ADDR_WIDTH + 2)-1; i = i + 1)
            res = res | (res >> 2**i);
        return res;
    endfunction

    /**
     * @brief Function counts the number of 0 from [64:13]
     * @param val value to extract count the zerios.
     * @returns the number of zeros from [64:13].
     */
    function automatic ew_t count_zeros_msb(addrmwm2_t val);
        ew_t res = 0;
        for (int i = CAP_ADDR_WIDTH - (CAP_M_WIDTH-1); i >=0; i = i - 1) begin
            if(!val[i]) res = res + 1;
            else return res;
        end
        return res;
    endfunction

    /**
     * @brief Function to decode from compressed bounds to decoded bounds
     * @param cbounds compressed bounds in memory.
     * @param format  bounds format
     * @returns the decoded bounds.
     */
    function automatic cap_bounds_t decode_bounds (cap_cbounds_t cbounds, cap_fmt_t format);
        cap_bounds_t cap_bounds  = DEFAULT_BOUNDS_CAP;
        logic [1:0] l_carry_out  = 2'b00;
        logic [1:0] l_msb        = 2'b00;
        logic [1:0] dec_top_bits = 2'b00;

        case(format)
            EMBEDDED_EXP: begin
                cap_bounds.exp          = {cbounds.exp_fmt.exp_top_bits, cbounds.exp_fmt.exp_base_bits};
                /* if (cap_bounds.exp > CAP_RESET_EXP)
                    cap_bounds.exp = CAP_RESET_EXP; */
                cap_bounds.top_bits     = {2'b00, cbounds.exp_fmt.top_bits, 3'b000};
                cap_bounds.base_bits    = {cbounds.exp_fmt.base_bits, 3'b000};
            end
            EXP0: begin
                cap_bounds.exp          = '{default: 0};
                cap_bounds.top_bits     = {2'b00, cbounds.exp0_fmt.top[11:0]};
                cap_bounds.base_bits    = cbounds.exp0_fmt.base;
            end
            default:;
        endcase

        l_carry_out = (cap_bounds.top_bits[11:0] < cap_bounds.base_bits[11:0]) ?
                                                                         2'b01 :
                                                                         2'b00;
        l_msb = (format == EXP0) ? 2'b00 : 2'b01;
        dec_top_bits = cap_bounds.base_bits[13:12] + l_carry_out + l_msb;

        cap_bounds.top_bits = {dec_top_bits, cap_bounds.top_bits[11:0]};
        return cap_bounds;
    endfunction

    /**
     * @brief Function to encode from decoded bounds to compressed bounds
     * @param bounds decoded bounds in register capability.
     * @param format bounds format
     * @returns the compressed bounds encoded format.
     */
    function automatic cap_cbounds_t encode_bounds (cap_bounds_t bounds, cap_fmt_t format);
        cap_cbounds_t cap_cbounds = DEFAULT_CBOUNDS_CAP;
        hew_t exp_msb  = bounds.exp[CAP_E_WIDTH - 1:CAP_E_HALF_WIDTH];
        hew_t exp_lsb  = bounds.exp[CAP_E_HALF_WIDTH - 1:0];
        hcmw_t top_bits =  bounds.top_bits[CAP_M_WIDTH-3:CAP_E_HALF_WIDTH];
        hmw_t base_bits = bounds.base_bits[CAP_M_WIDTH-1:CAP_E_HALF_WIDTH];

        /* if (bounds.exp > CAP_RESET_EXP) begin
            exp_msb = 3'b110;
            exp_lsb = 3'b100;
        end */

        case(format)
            EXP0: begin
                cap_cbounds.cbounds.top_bits  = bounds.top_bits[CAP_M_WIDTH-3:0];
                cap_cbounds.cbounds.base_bits = bounds.base_bits;
            end
            EMBEDDED_EXP: begin
                cap_cbounds.cbounds.top_bits  = {top_bits, exp_msb};
                cap_cbounds.cbounds.base_bits = {base_bits, exp_lsb};
            end
            default:;
        endcase
        return cap_cbounds;
    endfunction
    //TODO-cheri(ninolomata): Wrappers for the CHERI API standard
endpackage

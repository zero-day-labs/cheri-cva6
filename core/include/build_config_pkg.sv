package build_config_pkg;

  function automatic config_pkg::cva6_cfg_t build_config(config_pkg::cva6_user_cfg_t CVA6Cfg);
    bit IS_XLEN32 = (CVA6Cfg.XLEN == 32) ? 1'b1 : 1'b0;
    bit IS_XLEN64 = (CVA6Cfg.XLEN == 32) ? 1'b0 : 1'b1;
    bit FpPresent = CVA6Cfg.RVF | CVA6Cfg.RVD | CVA6Cfg.XF16 | CVA6Cfg.XF16ALT | CVA6Cfg.XF8;
    bit CheriPresent = CVA6Cfg.RVZcheripurecap | CVA6Cfg.RVZcherihybrid;
    bit NSX = CVA6Cfg.XF16 | CVA6Cfg.XF16ALT | CVA6Cfg.XF8 | CVA6Cfg.XFVec;  // Are non-standard extensions present?
    int unsigned FLen = CVA6Cfg.RVD ? 64 :  // D ext.
    CVA6Cfg.RVF ? 32 :  // F ext.
    CVA6Cfg.XF16 ? 16 :  // Xf16 ext.
    CVA6Cfg.XF16ALT ? 16 :  // Xf16alt ext.
    CVA6Cfg.XF8 ? 8 :  // Xf8 ext.
    1;  // Unused in case of no FP

    // Transprecision floating-point extensions configuration
    bit RVFVec     = CVA6Cfg.RVF     & CVA6Cfg.XFVec & FLen>32; // FP32 vectors available if vectors and larger fmt enabled
    bit XF16Vec    = CVA6Cfg.XF16    & CVA6Cfg.XFVec & FLen>16; // FP16 vectors available if vectors and larger fmt enabled
    bit XF16ALTVec = CVA6Cfg.XF16ALT & CVA6Cfg.XFVec & FLen>16; // FP16ALT vectors available if vectors and larger fmt enabled
    bit XF8Vec     = CVA6Cfg.XF8     & CVA6Cfg.XFVec & FLen>8;  // FP8 vectors available if vectors and larger fmt enabled

    bit EnableAccelerator = CVA6Cfg.RVV;  // Currently only used by V extension (Ara)
    int unsigned NrWbPorts = (CVA6Cfg.CvxifEn || EnableAccelerator) ? 5 : 4;

    int unsigned ICACHE_INDEX_WIDTH = $clog2(CVA6Cfg.IcacheByteSize / CVA6Cfg.IcacheSetAssoc);
    int unsigned DCACHE_INDEX_WIDTH = $clog2(CVA6Cfg.DcacheByteSize / CVA6Cfg.DcacheSetAssoc);
    int unsigned DCACHE_OFFSET_WIDTH = $clog2(CVA6Cfg.DcacheLineWidth / 8);

    // MMU
    int unsigned VpnLen = (CVA6Cfg.XLEN == 64) ? (CVA6Cfg.RVH ? 29 : 27) : 20;
    int unsigned PtLevels = (CVA6Cfg.XLEN == 64) ? 3 : 2;

    config_pkg::cva6_cfg_t cfg;

    cfg.XLEN = CVA6Cfg.XLEN;
    cfg.CLEN = CheriPresent ? (CVA6Cfg.XLEN * 2) : CVA6Cfg.XLEN;
    cfg.VLEN = (CVA6Cfg.XLEN == 32) ? 32 : 64;
    cfg.PLEN = (CVA6Cfg.XLEN == 32) ? 34 : 56;
    cfg.GPLEN = (CVA6Cfg.XLEN == 32) ? 34 : 41;
    cfg.REGLEN = CheriPresent ? $bits(cva6_cheri_pkg::cap_reg_t) : cfg.XLEN;
    cfg.PCLEN = CheriPresent ? $bits(cva6_cheri_pkg::cap_pcc_t) : cfg.VLEN;
    cfg.IS_XLEN32 = IS_XLEN32;
    cfg.IS_XLEN64 = IS_XLEN64;
    cfg.XLEN_ALIGN_BYTES = $clog2(CVA6Cfg.XLEN / 8);
    cfg.CLEN_ALIGN_BYTES = $clog2(cfg.CLEN / 8);
    cfg.ASID_WIDTH = (CVA6Cfg.XLEN == 64) ? 16 : 1;
    cfg.VMID_WIDTH = (CVA6Cfg.XLEN == 64) ? 14 : 1;

    cfg.FpgaEn = CVA6Cfg.FpgaEn;
    cfg.NrCommitPorts = CVA6Cfg.NrCommitPorts;
    cfg.NrLoadPipeRegs = CVA6Cfg.NrLoadPipeRegs;
    cfg.NrStorePipeRegs = CVA6Cfg.NrStorePipeRegs;
    cfg.AxiAddrWidth = CVA6Cfg.AxiAddrWidth;
    cfg.AxiDataWidth = CVA6Cfg.AxiDataWidth;
    cfg.AxiIdWidth = CVA6Cfg.AxiIdWidth;
    cfg.AxiUserWidth = CVA6Cfg.AxiUserWidth;
    cfg.MEM_TID_WIDTH = CVA6Cfg.MemTidWidth;
    cfg.NrLoadBufEntries = CVA6Cfg.NrLoadBufEntries;
    cfg.RVF = CVA6Cfg.RVF;
    cfg.RVD = CVA6Cfg.RVD;
    cfg.XF16 = CVA6Cfg.XF16;
    cfg.XF16ALT = CVA6Cfg.XF16ALT;
    cfg.XF8 = CVA6Cfg.XF8;
    cfg.RVA = CVA6Cfg.RVA;
    cfg.RVB = CVA6Cfg.RVB;
    cfg.RVV = CVA6Cfg.RVV;
    cfg.RVC = CVA6Cfg.RVC;
    cfg.RVH = CVA6Cfg.RVH;
    cfg.RVZCB = CVA6Cfg.RVZCB;
    cfg.RVZCMP = CVA6Cfg.RVZCMP;
    cfg.XFVec = CVA6Cfg.XFVec;
    cfg.CvxifEn = CVA6Cfg.CvxifEn;
    cfg.RVZiCond = CVA6Cfg.RVZiCond;
    cfg.RVZcheripurecap = CVA6Cfg.RVZcheripurecap;
    cfg.RVZcherihybrid = CVA6Cfg.RVZcherihybrid;
    cfg.NR_SB_ENTRIES = CVA6Cfg.NrScoreboardEntries;
    cfg.TRANS_ID_BITS = $clog2(CVA6Cfg.NrScoreboardEntries);

    cfg.FpPresent = bit'(FpPresent);
    cfg.CheriPresent = bit'(CheriPresent);
    cfg.NSX = bit'(NSX);
    cfg.FLen = unsigned'(FLen);
    cfg.RVFVec = bit'(RVFVec);
    cfg.XF16Vec = bit'(XF16Vec);
    cfg.XF16ALTVec = bit'(XF16ALTVec);
    cfg.XF8Vec = bit'(XF8Vec);
    cfg.NrRgprPorts = unsigned'(2);
    cfg.NrWbPorts = unsigned'(NrWbPorts);
    cfg.EnableAccelerator = bit'(EnableAccelerator);
    cfg.PerfCounterEn = CVA6Cfg.PerfCounterEn;
    cfg.MmuPresent = CVA6Cfg.MmuPresent;
    cfg.RVS = CVA6Cfg.RVS;
    cfg.RVU = CVA6Cfg.RVU;

    cfg.HaltAddress = CVA6Cfg.HaltAddress;
    cfg.ExceptionAddress = CVA6Cfg.ExceptionAddress;
    cfg.RASDepth = CVA6Cfg.RASDepth;
    cfg.BTBEntries = CVA6Cfg.BTBEntries;
    cfg.BHTEntries = CVA6Cfg.BHTEntries;
    cfg.DmBaseAddress = CVA6Cfg.DmBaseAddress;
    cfg.TvalEn = CVA6Cfg.TvalEn;
    cfg.NrPMPEntries = CVA6Cfg.NrPMPEntries;
    cfg.PMPCfgRstVal = CVA6Cfg.PMPCfgRstVal;
    cfg.PMPAddrRstVal = CVA6Cfg.PMPAddrRstVal;
    cfg.PMPEntryReadOnly = CVA6Cfg.PMPEntryReadOnly;
    cfg.NOCType = CVA6Cfg.NOCType;
    cfg.NrNonIdempotentRules = CVA6Cfg.NrNonIdempotentRules;
    cfg.NonIdempotentAddrBase = CVA6Cfg.NonIdempotentAddrBase;
    cfg.NonIdempotentLength = CVA6Cfg.NonIdempotentLength;
    cfg.NrExecuteRegionRules = CVA6Cfg.NrExecuteRegionRules;
    cfg.ExecuteRegionAddrBase = CVA6Cfg.ExecuteRegionAddrBase;
    cfg.ExecuteRegionLength = CVA6Cfg.ExecuteRegionLength;
    cfg.NrCachedRegionRules = CVA6Cfg.NrCachedRegionRules;
    cfg.CachedRegionAddrBase = CVA6Cfg.CachedRegionAddrBase;
    cfg.CachedRegionLength = CVA6Cfg.CachedRegionLength;
    cfg.MaxOutstandingStores = CVA6Cfg.MaxOutstandingStores;
    cfg.DebugEn = CVA6Cfg.DebugEn;
    cfg.NonIdemPotenceEn = (CVA6Cfg.NrNonIdempotentRules > 0) && (CVA6Cfg.NonIdempotentLength > 0);
    cfg.AxiBurstWriteEn = CVA6Cfg.AxiBurstWriteEn;

    cfg.ICACHE_SET_ASSOC = CVA6Cfg.IcacheSetAssoc;
    cfg.ICACHE_SET_ASSOC_WIDTH = $clog2(CVA6Cfg.IcacheSetAssoc);
    cfg.ICACHE_INDEX_WIDTH = ICACHE_INDEX_WIDTH;
    cfg.ICACHE_TAG_WIDTH = cfg.PLEN - ICACHE_INDEX_WIDTH;
    cfg.ICACHE_LINE_WIDTH = CVA6Cfg.IcacheLineWidth;
    cfg.ICACHE_USER_LINE_WIDTH = (CVA6Cfg.AxiUserWidth == 1) ? 4 : CVA6Cfg.IcacheLineWidth;
    cfg.DCacheType = CVA6Cfg.DCacheType;
    cfg.DcacheIdWidth = CVA6Cfg.DcacheIdWidth;
    cfg.DCACHE_SET_ASSOC = CVA6Cfg.DcacheSetAssoc;
    cfg.DCACHE_SET_ASSOC_WIDTH = $clog2(CVA6Cfg.DcacheSetAssoc);
    cfg.DCACHE_INDEX_WIDTH = DCACHE_INDEX_WIDTH;
    cfg.DCACHE_TAG_WIDTH = cfg.PLEN - DCACHE_INDEX_WIDTH;
    cfg.DCACHE_LINE_WIDTH = CVA6Cfg.DcacheLineWidth;
    cfg.DCACHE_USER_LINE_WIDTH = (CVA6Cfg.AxiUserWidth == 1) ? 4 : CVA6Cfg.DcacheLineWidth;
    cfg.DCACHE_USER_WIDTH = CVA6Cfg.AxiUserWidth;
    cfg.DCACHE_OFFSET_WIDTH = DCACHE_OFFSET_WIDTH;
    cfg.DCACHE_DATA_SIZE_WIDTH = (cfg.CheriPresent && cfg.IS_XLEN64) ? 3 : 2;
    cfg.DCACHE_NUM_WORDS = 2 ** (DCACHE_INDEX_WIDTH - DCACHE_OFFSET_WIDTH);

    cfg.DCACHE_MAX_TX = unsigned'(2 ** CVA6Cfg.MemTidWidth);

    cfg.CheriCapTagWidth = CVA6Cfg.CheriCapTagWidth;
    cfg.RVFI_DII = bit'(CVA6Cfg.RVFI_DII);

    cfg.DATA_USER_EN = CVA6Cfg.DataUserEn;
    cfg.WtDcacheWbufDepth = CVA6Cfg.WtDcacheWbufDepth;
    cfg.FETCH_USER_WIDTH = CVA6Cfg.FetchUserWidth;
    cfg.FETCH_USER_EN = CVA6Cfg.FetchUserEn;
    cfg.AXI_USER_EN = CVA6Cfg.DataUserEn | CVA6Cfg.FetchUserEn;

    cfg.FETCH_WIDTH = 32 << ariane_pkg::SUPERSCALAR;
    cfg.FETCH_ALIGN_BITS = $clog2(cfg.FETCH_WIDTH / 8);
    cfg.INSTR_PER_FETCH = cfg.FETCH_WIDTH / ((CVA6Cfg.RVC) ? 16 : 32);
    cfg.LOG2_INSTR_PER_FETCH = cfg.INSTR_PER_FETCH > 1 ? $clog2(cfg.INSTR_PER_FETCH) : 1;

    cfg.ModeW = (CVA6Cfg.XLEN == 32) ? 1 : 4;
    cfg.ASIDW = (CVA6Cfg.XLEN == 32) ? 9 : 16;
    cfg.VMIDW = (CVA6Cfg.XLEN == 32) ? 7 : 14;
    cfg.PPNW = (CVA6Cfg.XLEN == 32) ? 22 : 44;
    cfg.GPPNW = (CVA6Cfg.XLEN == 32) ? 22 : 29;
    cfg.MODE_SV = (CVA6Cfg.XLEN == 32) ? config_pkg::ModeSv32 : config_pkg::ModeSv39;
    cfg.SV = (cfg.MODE_SV == config_pkg::ModeSv32) ? 32 : 39;
    cfg.SVX = (cfg.MODE_SV == config_pkg::ModeSv32) ? 34 : 41;
    cfg.InstrTlbEntries = CVA6Cfg.InstrTlbEntries;
    cfg.DataTlbEntries = CVA6Cfg.DataTlbEntries;
    cfg.UseSharedTlb = CVA6Cfg.UseSharedTlb;
    cfg.SharedTlbDepth = CVA6Cfg.SharedTlbDepth;
    cfg.VpnLen = VpnLen;
    cfg.PtLevels = PtLevels;

    return cfg;
  endfunction

endpackage

// Copyright 2022 Thales DIS design services SAS
//
// Licensed under the Solderpad Hardware Licence, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.0
// You may obtain a copy of the License at https://solderpad.org/licenses/
//
// Original Author: Jean-Roch COULON - Thales

package cva6_config_pkg;

  localparam CVA6ConfigXlen = 32;

  localparam CVA6ConfigBExtEn = 1;  // UVM
  localparam CVA6ConfigNrCommitPorts = 1;  // UVM
  localparam CVA6ConfigRvfiTrace = 1;

  localparam CVA6ConfigRVZcheripurecap = 0;
  localparam CVA6ConfigRVZcherihybrid = 0;

  localparam CVA6ConfigAxiIdWidth = 4;  // axi_pkg.sv
  localparam CVA6ConfigAxiAddrWidth = 64;  // axi_pkg.sv
  localparam CVA6ConfigAxiDataWidth = 64;  // axi_pkg.sv
  localparam CVA6ConfigDataUserWidth = 32;  // axi_pkg.sv

  localparam CVA6ConfigWtDcacheWbufDepth = 2;  // wtcache

  localparam CVA6ConfigSuperscalarEn = 0;  // superscalar

  localparam CVA6ConfigNrScoreboardEntries = 4;  // cvxif_pkg.sv

  localparam config_pkg::cva6_user_cfg_t cva6_cfg = '{
      XLEN: unsigned'(CVA6ConfigXlen),
      FpgaEn: bit'(0),
      NrCommitPorts: unsigned'(CVA6ConfigNrCommitPorts),
      AxiAddrWidth: unsigned'(CVA6ConfigAxiAddrWidth),
      AxiDataWidth: unsigned'(CVA6ConfigAxiDataWidth),
      AxiIdWidth: unsigned'(CVA6ConfigAxiIdWidth),
      AxiUserWidth: unsigned'(CVA6ConfigDataUserWidth),
      MemTidWidth: unsigned'(CVA6ConfigAxiIdWidth),
      NrLoadBufEntries: unsigned'(2),
      RVF: bit'(0),
      RVD: bit'(0),
      XF16: bit'(0),
      XF16ALT: bit'(0),
      XF8: bit'(0),
      RVA: bit'(0),
      RVB: bit'(CVA6ConfigBExtEn),
      RVV: bit'(0),
      RVC: bit'(1),
      RVH: bit'(0),
      RVZCB: bit'(1),
      RVZCMP: bit'(0),
      XFVec: bit'(0),
      CvxifEn: bit'(1),
      RVZiCond: bit'(0),
      RVZcheripurecap: bit'(0),
      RVZcherihybrid: bit'(0),
      NrScoreboardEntries: unsigned'(CVA6ConfigNrScoreboardEntries),
      PerfCounterEn: bit'(0),
      MmuPresent: bit'(0),
      RVS: bit'(0),
      RVU: bit'(0),
      HaltAddress: 64'h800,
      ExceptionAddress: 64'h808,
      RASDepth: unsigned'(2),
      BTBEntries: unsigned'(0),
      BHTEntries: unsigned'(32),
      DmBaseAddress: 64'h0,
      TvalEn: bit'(0),
      NrPMPEntries: unsigned'(8),
      PMPCfgRstVal: {16{64'h0}},
      PMPAddrRstVal: {16{64'h0}},
      PMPEntryReadOnly: 16'd0,
      NOCType: config_pkg::NOC_TYPE_AXI4_ATOP,
      NrNonIdempotentRules: unsigned'(2),
      NonIdempotentAddrBase: 1024'({64'b0, 64'b0}),
      NonIdempotentLength: 1024'({64'b0, 64'b0}),
      NrExecuteRegionRules: unsigned'(3),
      ExecuteRegionAddrBase: 1024'({64'h8000_0000, 64'h1_0000, 64'h0}),
      ExecuteRegionLength: 1024'({64'h40000000, 64'h10000, 64'h1000}),
      NrCachedRegionRules: unsigned'(1),
      CachedRegionAddrBase: 1024'({64'h8000_0000}),
      CachedRegionLength: 1024'({64'h40000000}),
      MaxOutstandingStores: unsigned'(7),
      DebugEn: bit'(0),
      AxiBurstWriteEn: bit'(0),
      IcacheByteSize: unsigned'(2048),
      IcacheSetAssoc: unsigned'(2),
      IcacheLineWidth: unsigned'(128),
      DCacheType: config_pkg::HPDCACHE,
      DcacheByteSize: unsigned'(32768),
      DcacheSetAssoc: unsigned'(8),
      DcacheLineWidth: unsigned'(128),
      DataUserEn: unsigned'(0),
      WtDcacheWbufDepth: int'(2),
      FetchUserWidth: unsigned'(32),
      FetchUserEn: unsigned'(0),
      InstrTlbEntries: int'(2),
      DataTlbEntries: int'(2),
      UseSharedTlb: bit'(1),
      SharedTlbDepth: int'(64),
      NrLoadPipeRegs: int'(0),
      NrStorePipeRegs: int'(0),
      DcacheIdWidth: int'(1),
      CheriCapTagWidth : int'(1),
      RVFI_DII : int'(0)
  };

endpackage

// =============================================================================
// TZANiX Æther Core - Synthesizable SystemVerilog Cycle-Accurate Testbench
// Target: Verilator / Xilinx Vivado XSIM / ModelSim
// Simulates 400 MHz clock (2500 ps period) and verifies 10.0 ns Cut-Through
// latency across the 4-stage Q16.16 pipeline.
// =============================================================================

`timescale 1ps / 1ps

module tb_tzanix_aether;

    // 400 MHz Clock (Period = 2500 ps = 2.5 ns)
    logic         clk_400m = 1'b0;
    logic         rst_n    = 1'b0;
    always #1250 clk_400m = ~clk_400m;

    // Hardware CSRs (Q16.16)
    // Drop threshold = 2.10 * 65536 = 137625
    // GPU FFT threshold = 2.25 * 65536 = 147456
    logic [31:0]  csr_drop_threshold_q16    = 32'd137625;
    logic [31:0]  csr_gpu_fft_threshold_q16 = 32'd147456;

    // AXI4-Stream Slave Signals (512-bit)
    logic [511:0] s_axis_tdata;
    logic [63:0]  s_axis_tkeep;
    logic         s_axis_tvalid;
    logic         s_axis_tlast;
    logic         s_axis_tuser_bypass;
    wire          s_axis_tready;

    // AXI4-Stream Master Signals (512-bit)
    wire [511:0]  m_axis_tdata;
    wire [63:0]   m_axis_tkeep;
    wire          m_axis_tvalid;
    wire          m_axis_tlast;
    wire          m_axis_tuser_drop;
    wire          m_axis_tuser_gpu_fft;
    wire [31:0]   m_axis_entropy_q16;

    // Instantiate DUT (Device Under Test)
    tzanix_aether_fpga #(
        .CHANNELS(16),
        .LUT_DEPTH(512),
        .LUT_ADDR_WIDTH(9),
        .Q16_WIDTH(32)
    ) dut (
        .clk_400m(clk_400m),
        .rst_n(rst_n),
        .csr_drop_threshold_q16(csr_drop_threshold_q16),
        .csr_gpu_fft_threshold_q16(csr_gpu_fft_threshold_q16),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tkeep(s_axis_tkeep),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .s_axis_tuser_bypass(s_axis_tuser_bypass),
        .s_axis_tready(s_axis_tready),
        .m_axis_tdata(m_axis_tdata),
        .m_axis_tkeep(m_axis_tkeep),
        .m_axis_tvalid(m_axis_tvalid),
        .m_axis_tlast(m_axis_tlast),
        .m_axis_tuser_drop(m_axis_tuser_drop),
        .m_axis_tuser_gpu_fft(m_axis_tuser_gpu_fft),
        .m_axis_entropy_q16(m_axis_entropy_q16)
    );

    // Helper task to pack 16x 32-bit channels into 512-bit AXI4-Stream flit
    task automatic drive_flit(
        input logic [31:0] c0,  input logic [31:0] c1,  input logic [31:0] c2,  input logic [31:0] c3,
        input logic [31:0] c4,  input logic [31:0] c5,  input logic [31:0] c6,  input logic [31:0] c7,
        input logic [31:0] c8,  input logic [31:0] c9,  input logic [31:0] c10, input logic [31:0] c11,
        input logic [31:0] c12, input logic [31:0] c13, input logic [31:0] c14, input logic [31:0] c15
    );
        s_axis_tdata = {c15, c14, c13, c12, c11, c10, c9, c8, c7, c6, c5, c4, c3, c2, c1, c0};
        s_axis_tkeep = 64'hFFFF_FFFF_FFFF_FFFF;
        s_axis_tvalid = 1'b1;
        s_axis_tlast  = 1'b1;
        s_axis_tuser_bypass = 1'b0;
    endtask

    initial begin
        // Export waveform for GTKWave / Vivado
        $dumpfile("tzanix_trident_waves.vcd");
        $dumpvars(0, tb_tzanix_aether);

        // Pre-initialize essential BRAM entries in Q16.16 (Matches SHANNON_BRAM_Q16 in Rust)
        for (int b = 0; b < 16; b++) begin
            for (int addr = 0; addr < 512; addr++) begin
                dut.shannon_bram[b][addr] = 32'd0;
            end
            // Entry 32 (~1/16th uniform density): 0.250312 * 65536 = 16404
            dut.shannon_bram[b][32]  = 32'd16404;
            // Entry 511 (100% single-channel DDoS concentration): 0
            dut.shannon_bram[b][511] = 32'd0;
        end

        s_axis_tdata  = 512'd0;
        s_axis_tkeep  = 64'd0;
        s_axis_tvalid = 1'b0;
        s_axis_tlast  = 1'b0;
        s_axis_tuser_bypass = 1'b0;

        // Release Reset after 4 clock cycles (10 ns)
        repeat (4) @(posedge clk_400m);
        rst_n = 1'b1;
        @(posedge clk_400m);

        $display("=========================================================================");
        $display(" [RTL TB] Starting 400 MHz (2.5 ns/cycle) AXI4-Stream 512-bit Burst Test");
        $display("=========================================================================");

        // Cycle T=0: Inject Uniform Legitimate Traffic (All 16 channels = 100)
        drive_flit(
            32'd100, 32'd100, 32'd100, 32'd100, 32'd100, 32'd100, 32'd100, 32'd100,
            32'd100, 32'd100, 32'd100, 32'd100, 32'd100, 32'd100, 32'd100, 32'd100
        );
        @(posedge clk_400m);

        // Cycle T=1 (Back-to-Back 100GbE): Inject Collapsed DDoS Flood (Single channel = 999999)
        drive_flit(
            32'd999999, 32'd0, 32'd0, 32'd0, 32'd0, 32'd0, 32'd0, 32'd0,
            32'd0,      32'd0, 32'd0, 32'd0, 32'd0, 32'd0, 32'd0, 32'd0
        );
        @(posedge clk_400m);

        // De-assert valid
        s_axis_tvalid = 1'b0;

        // Wait 3 more cycles for Pipeline Stage 4 output of Flit #1 (Total 4 cycles = 10.0 ns)
        repeat (2) @(posedge clk_400m);
        #100; // Sample slightly after clock edge
        $display("[T + 10.0 ns] Flit #1 (Uniform Legit) -> m_axis_entropy_q16 = %0d | drop = %b | gpu_fft = %b",
                 m_axis_entropy_q16, m_axis_tuser_drop, m_axis_tuser_gpu_fft);
        assert(m_axis_tvalid == 1'b1) else $fatal(1, "Expected m_axis_tvalid == 1");
        assert(m_axis_tuser_drop == 1'b0) else $fatal(1, "Legitimate uniform flit must NOT be dropped!");

        @(posedge clk_400m);
        #100;
        $display("[T + 12.5 ns] Flit #2 (Collapsed DDoS) -> m_axis_entropy_q16 = %0d | drop = %b | gpu_fft = %b",
                 m_axis_entropy_q16, m_axis_tuser_drop, m_axis_tuser_gpu_fft);
        assert(m_axis_tvalid == 1'b1) else $fatal(1, "Expected m_axis_tvalid == 1");
        assert(m_axis_tuser_drop == 1'b1) else $fatal(1, "Collapsed DDoS flit MUST trigger instant Cut-Through Drop!");

        $display("=========================================================================");
        $display(" [RTL TB] SUCCESS: All 4-Stage Pipeline Timing & Cut-Through Assertions Passed!");
        $display("=========================================================================");
        $finish;
    end

endmodule

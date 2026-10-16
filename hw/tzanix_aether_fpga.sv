// =============================================================================
// TZANiX Æther Core - Synthesizable SystemVerilog RTL (400 MHz / 100GbE Line-Rate)
// Architecture: Trident Silicon First-Line Shield (Xilinx UltraScale+ / Agilex)
// Clock Frequency: 400 MHz (2.5 ns period) | Pipeline Depth: 4 Cycles (10.0 ns)
// Data Bus: AXI4-Stream 512-bit (64 Bytes per Flit - DenseSignalSnapshot)
// Arithmetic: Fixed-Point Q16.16 (Zero-FPU, 16x Parallel Dual-Port BRAM Banks)
// =============================================================================

`timescale 1ps / 1ps
`default_nettype none

module tzanix_aether_fpga #(
    parameter int CHANNELS        = 16,          // 8 Alpha + 8 Beta channels (32-bit each = 512-bit)
    parameter int LUT_DEPTH       = 512,         // 512 entries in Shannon BRAM
    parameter int LUT_ADDR_WIDTH  = 9,           // log2(512)
    parameter int Q16_WIDTH       = 32           // Unsigned Q16.16 fixed-point representation
) (
    input  wire                     clk_400m,    // 400 MHz Core Clock (2500 ps period)
    input  wire                     rst_n,       // Active-low synchronous reset

    // Hot-Reloadable Hardware CSRs (Control & Status Registers via AXI4-Lite / PCIe BAR)
    input  wire [Q16_WIDTH-1:0]     csr_drop_threshold_q16,
    input  wire [Q16_WIDTH-1:0]     csr_gpu_fft_threshold_q16,

    // AXI4-Stream Slave Interface (From 100G QSFP28 MAC RX)
    input  wire [511:0]             s_axis_tdata,
    input  wire [63:0]              s_axis_tkeep,
    input  wire                     s_axis_tvalid,
    input  wire                     s_axis_tlast,
    input  wire                     s_axis_tuser_bypass,
    output wire                     s_axis_tready,

    // AXI4-Stream Master Interface (Cut-Through to Host DMA / RoCEv2 RDMA TX)
    output logic [511:0]            m_axis_tdata,
    output logic [63:0]             m_axis_tkeep,
    output logic                    m_axis_tvalid,
    output logic                    m_axis_tlast,
    output logic                    m_axis_tuser_drop,       // Instant Cut-Through MAC Abort
    output logic                    m_axis_tuser_gpu_fft,    // GPUDirect RDMA FFT Trigger
    output logic [Q16_WIDTH-1:0]    m_axis_entropy_q16       // Computed Q16.16 Shannon Entropy
);

    // Always ready for 100GbE zero-backpressure line-rate operation
    assign s_axis_tready = 1'b1;

    // =========================================================================
    // 16-Bank Parallel BRAM Array for 1-Cycle Simultaneous Channel Lookups
    // In Vivado/Quartus, (* ram_style = "block" *) synthesizes to 18Kb BRAMs.
    // =========================================================================
    (* ram_style = "block" *) logic [Q16_WIDTH-1:0] shannon_bram [0:CHANNELS-1][0:LUT_DEPTH-1];

    // Unpack 512-bit AXI4-Stream bus into 16 parallel 32-bit channels
    wire [31:0] ch_in [0:CHANNELS-1];
    genvar g;
    generate
        for (g = 0; g < CHANNELS; g = g + 1) begin : gen_unpack
            assign ch_in[g] = s_axis_tdata[g*32 +: 32];
        end
    endgenerate

    // =========================================================================
    // STAGE 1 (T + 2.5 ns): Parallel Adder Tree across 16 Channels
    // =========================================================================
    logic [63:0]  st1_total_density;
    logic [31:0]  st1_ch_val [0:CHANNELS-1];
    logic [511:0] st1_tdata;
    logic [63:0]  st1_tkeep;
    logic         st1_tvalid;
    logic         st1_tlast;
    logic         st1_bypass;

    always_ff @(posedge clk_400m) begin
        if (!rst_n) begin
            st1_total_density <= 64'd0;
            st1_tvalid        <= 1'b0;
            st1_tlast         <= 1'b0;
            st1_bypass        <= 1'b0;
        end else begin
            st1_tvalid <= s_axis_tvalid;
            st1_tlast  <= s_axis_tlast;
            st1_bypass <= s_axis_tuser_bypass;
            st1_tdata  <= s_axis_tdata;
            st1_tkeep  <= s_axis_tkeep;

            for (int i = 0; i < CHANNELS; i++) begin
                st1_ch_val[i] <= ch_in[i];
            end

            // Balanced 16-input combinational adder tree
            st1_total_density <=
                (64'(ch_in[0])  + 64'(ch_in[1])  + 64'(ch_in[2])  + 64'(ch_in[3]))  +
                (64'(ch_in[4])  + 64'(ch_in[5])  + 64'(ch_in[6])  + 64'(ch_in[7]))  +
                (64'(ch_in[8])  + 64'(ch_in[9])  + 64'(ch_in[10]) + 64'(ch_in[11])) +
                (64'(ch_in[12]) + 64'(ch_in[13]) + 64'(ch_in[14]) + 64'(ch_in[15]));
        end
    end

    // =========================================================================
    // STAGE 2 (T + 5.0 ns): DSP Normalization & 16-Port BRAM Parallel Read
    // =========================================================================
    logic [Q16_WIDTH-1:0] st2_bram_out [0:CHANNELS-1];
    logic [511:0]         st2_tdata;
    logic [63:0]          st2_tkeep;
    logic                 st2_tvalid;
    logic                 st2_tlast;
    logic                 st2_bypass;
    logic                 st2_zero_density;

    always_ff @(posedge clk_400m) begin
        if (!rst_n) begin
            st2_tvalid       <= 1'b0;
            st2_tlast        <= 1'b0;
            st2_bypass       <= 1'b0;
            st2_zero_density <= 1'b1;
        end else begin
            st2_tvalid       <= st1_tvalid;
            st2_tlast        <= st1_tlast;
            st2_bypass       <= st1_bypass;
            st2_tdata        <= st1_tdata;
            st2_tkeep        <= st1_tkeep;
            st2_zero_density <= (st1_total_density == 64'd0);

            for (int c = 0; c < CHANNELS; c++) begin
                if (st1_total_density == 64'd0) begin
                    st2_bram_out[c] <= 32'd0;
                end else begin
                    // Hardware DSP scaling: idx = (ch_val * 511) / total_density
                    automatic logic [63:0] scaled_idx = (64'(st1_ch_val[c]) * 64'd511) / st1_total_density;
                    automatic logic [LUT_ADDR_WIDTH-1:0] clamped_addr =
                        (scaled_idx > 64'd511) ? 9'd511 : scaled_idx[LUT_ADDR_WIDTH-1:0];
                    st2_bram_out[c] <= shannon_bram[c][clamped_addr];
                end
            end
        end
    end

    // =========================================================================
    // STAGE 3 (T + 7.5 ns): Fixed-Point Q16.16 Entropy Accumulator Tree
    // =========================================================================
    logic [Q16_WIDTH-1:0] st3_entropy_q16;
    logic [511:0]         st3_tdata;
    logic [63:0]          st3_tkeep;
    logic                 st3_tvalid;
    logic                 st3_tlast;
    logic                 st3_bypass;
    logic                 st3_zero_density;

    always_ff @(posedge clk_400m) begin
        if (!rst_n) begin
            st3_entropy_q16  <= 32'd0;
            st3_tvalid       <= 1'b0;
            st3_tlast        <= 1'b0;
            st3_bypass       <= 1'b0;
            st3_zero_density <= 1'b1;
        end else begin
            st3_tvalid       <= st2_tvalid;
            st3_tlast        <= st2_tlast;
            st3_bypass       <= st2_bypass;
            st3_tdata        <= st2_tdata;
            st3_tkeep        <= st2_tkeep;
            st3_zero_density <= st2_zero_density;

            if (st2_zero_density) begin
                st3_entropy_q16 <= 32'd0;
            end else begin
                st3_entropy_q16 <=
                    (st2_bram_out[0]  + st2_bram_out[1]  + st2_bram_out[2]  + st2_bram_out[3])  +
                    (st2_bram_out[4]  + st2_bram_out[5]  + st2_bram_out[6]  + st2_bram_out[7])  +
                    (st2_bram_out[8]  + st2_bram_out[9]  + st2_bram_out[10] + st2_bram_out[11]) +
                    (st2_bram_out[12] + st2_bram_out[13] + st2_bram_out[14] + st2_bram_out[15]);
            end
        end
    end

    // =========================================================================
    // STAGE 4 (T + 10.0 ns): Cut-Through Comparator & GPUDirect FFT Trigger
    // =========================================================================
    always_ff @(posedge clk_400m) begin
        if (!rst_n) begin
            m_axis_tvalid        <= 1'b0;
            m_axis_tlast         <= 1'b0;
            m_axis_tuser_drop    <= 1'b0;
            m_axis_tuser_gpu_fft <= 1'b0;
            m_axis_entropy_q16   <= 32'd0;
        end else begin
            m_axis_tvalid      <= st3_tvalid;
            m_axis_tlast       <= st3_tlast;
            m_axis_tdata       <= st3_tdata;
            m_axis_tkeep       <= st3_tkeep;
            m_axis_entropy_q16 <= st3_entropy_q16;

            // Deterministic Cut-Through Drop Decision
            if (!st3_bypass && (st3_zero_density || (st3_entropy_q16 < csr_drop_threshold_q16))) begin
                m_axis_tuser_drop    <= 1'b1;
                m_axis_tuser_gpu_fft <= 1'b0;
            end else if (!st3_bypass && (st3_entropy_q16 < csr_gpu_fft_threshold_q16)) begin
                m_axis_tuser_drop    <= 1'b0;
                m_axis_tuser_gpu_fft <= 1'b1; // Route to GPU via GPUDirect RDMA for FFT
            end else begin
                m_axis_tuser_drop    <= 1'b0;
                m_axis_tuser_gpu_fft <= 1'b0;
            end
        end
    end

endmodule
`default_nettype wire

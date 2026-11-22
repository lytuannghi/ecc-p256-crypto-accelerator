// =============================================================================
// File: ecc_regs_apb.v
// Module: ecc_regs_apb
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: AMBA 3 APB Slave Memory-Mapped Register Interface.
//              Provides standard 32-bit register read/write access to 256-bit
//              keys, points, scalars, and crypto command registers.
// =============================================================================

`timescale 1ns / 1ps

module ecc_regs_apb (
    input  wire        pclk,
    input  wire        presetn,

    // APB3 Interface
    input  wire [7:0]  paddr,
    input  wire        psel,
    input  wire        penable,
    input  wire        pwrite,
    input  wire [31:0] pwdata,
    output reg  [31:0] prdata,
    output wire        pready,
    output wire        pslverr,

    // Core Control Signals
    output reg         cmd_start,
    output reg  [1:0]  cmd_mode,       // 0: Scalar Mult, 1: Sign, 2: Verify
    output reg  [255:0] reg_point_x,
    output reg  [255:0] reg_point_y,
    output reg  [255:0] reg_scalar_k,
    output reg  [255:0] reg_hash_e,

    // Status from Core
    input  wire        core_busy,
    input  wire        core_done,
    input  wire        core_sig_valid,
    input  wire [255:0] core_res_x,
    input  wire [255:0] core_res_y
);

    assign pready  = 1'b1;
    assign pslverr = 1'b0;

    // Internal status latches
    reg done_latch;
    reg valid_latch;

    always @(posedge pclk or negedge presetn) begin
        if (!presetn) begin
            cmd_start   <= 1'b0;
            cmd_mode    <= 2'b00;
            reg_point_x <= 256'd0;
            reg_point_y <= 256'd0;
            reg_scalar_k<= 256'd0;
            reg_hash_e  <= 256'd0;
            prdata      <= 32'd0;
            done_latch  <= 1'b0;
            valid_latch <= 1'b0;
        end else begin
            cmd_start <= 1'b0; // Auto-clearing strobe

            if (core_done) begin
                done_latch  <= 1'b1;
                valid_latch <= core_sig_valid;
            end

            // APB Write Operation
            if (psel && penable && pwrite) begin
                case (paddr)
                    8'h00: begin
                        cmd_start <= pwdata[0];
                        cmd_mode  <= pwdata[3:2];
                        if (pwdata[1]) begin // W1C Done
                            done_latch  <= 1'b0;
                            valid_latch <= 1'b0;
                        end
                    end
                    // Point X registers (8 words)
                    8'h10: reg_point_x[31:0]    <= pwdata;
                    8'h14: reg_point_x[63:32]   <= pwdata;
                    8'h18: reg_point_x[95:64]   <= pwdata;
                    8'h1C: reg_point_x[127:96]  <= pwdata;
                    8'h20: reg_point_x[159:128] <= pwdata;
                    8'h24: reg_point_x[191:160] <= pwdata;
                    8'h28: reg_point_x[223:192] <= pwdata;
                    8'h2C: reg_point_x[255:224] <= pwdata;

                    // Point Y registers
                    8'h30: reg_point_y[31:0]    <= pwdata;
                    8'h34: reg_point_y[63:32]   <= pwdata;
                    8'h38: reg_point_y[95:64]   <= pwdata;
                    8'h3C: reg_point_y[127:96]  <= pwdata;
                    8'h40: reg_point_y[159:128] <= pwdata;
                    8'h44: reg_point_y[191:160] <= pwdata;
                    8'h48: reg_point_y[223:192] <= pwdata;
                    8'h4C: reg_point_y[255:224] <= pwdata;

                    // Scalar K / Nonce / Private Key
                    8'h50: reg_scalar_k[31:0]    <= pwdata;
                    8'h54: reg_scalar_k[63:32]   <= pwdata;
                    8'h58: reg_scalar_k[95:64]   <= pwdata;
                    8'h5C: reg_scalar_k[127:96]  <= pwdata;
                    8'h60: reg_scalar_k[159:128] <= pwdata;
                    8'h64: reg_scalar_k[191:160] <= pwdata;
                    8'h68: reg_scalar_k[223:192] <= pwdata;
                    8'h6C: reg_scalar_k[255:224] <= pwdata;

                    // Hash E
                    8'hB0: reg_hash_e[31:0]    <= pwdata;
                    8'hB4: reg_hash_e[63:32]   <= pwdata;
                    8'hB8: reg_hash_e[95:64]   <= pwdata;
                    8'hBC: reg_hash_e[127:96]  <= pwdata;
                    8'hC0: reg_hash_e[159:128] <= pwdata;
                    8'hC4: reg_hash_e[191:160] <= pwdata;
                    8'hC8: reg_hash_e[223:192] <= pwdata;
                    8'hCC: reg_hash_e[255:224] <= pwdata;
                    default: ;
                endcase
            end

            // APB Read Operation
            if (psel && !pwrite) begin
                case (paddr)
                    8'h00: prdata <= {28'd0, cmd_mode, 1'b0, cmd_start};
                    8'h04: prdata <= {28'd0, 1'b0, valid_latch, done_latch, core_busy};

                    // Read Result X / R
                    8'h70: prdata <= core_res_x[31:0];
                    8'h74: prdata <= core_res_x[63:32];
                    8'h78: prdata <= core_res_x[95:64];
                    8'h7C: prdata <= core_res_x[127:96];
                    8'h80: prdata <= core_res_x[159:128];
                    8'h84: prdata <= core_res_x[191:160];
                    8'h88: prdata <= core_res_x[223:192];
                    8'h8C: prdata <= core_res_x[255:224];

                    // Read Result Y / S
                    8'h90: prdata <= core_res_y[31:0];
                    8'h94: prdata <= core_res_y[63:32];
                    8'h98: prdata <= core_res_y[95:64];
                    8'h9C: prdata <= core_res_y[127:96];
                    8'hA0: prdata <= core_res_y[159:128];
                    8'hA4: prdata <= core_res_y[191:160];
                    8'hA8: prdata <= core_res_y[223:192];
                    8'hAC: prdata <= core_res_y[255:224];

                    default: prdata <= 32'd0;
                endcase
            end
        end
    end

endmodule

// =============================================================================
// File: mod_mult_256.v
// Module: mod_mult_256
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Constant-Time 256-bit Interleaved Modular Multiplier.
//              Computes: res = (a * b) mod p
//              Executes in exactly 256 clock cycles (constant-time, SPA-resistant).
// =============================================================================

`timescale 1ns / 1ps

module mod_mult_256 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] a,
    input  wire [255:0] b,
    input  wire [255:0] p,
    output reg  [255:0] res,
    output reg          done,
    output reg          busy
);

    reg [255:0] a_reg;
    reg [255:0] b_reg;
    reg [255:0] p_reg;
    reg [257:0] r_accum;     // Accumulator with guard bits
    reg [8:0]   bit_cnt;     // 256 cycles counter

    // Reduction wires (T < 3p, so at most 2 subtractions of p)
    wire [257:0] term_a = b_reg[255] ? {2'b00, a_reg} : 258'd0;
    wire [257:0] t_next = {r_accum[256:0], 1'b0} + term_a;

    wire [257:0] p_x1   = {2'b00, p_reg};
    wire [257:0] p_x2   = {1'b0, p_reg, 1'b0};

    wire [258:0] sub_p2 = {1'b0, t_next} - {1'b0, p_x2};
    wire [258:0] sub_p1 = {1'b0, t_next} - {1'b0, p_x1};

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            res     <= 256'd0;
            done    <= 1'b0;
            busy    <= 1'b0;
            a_reg   <= 256'd0;
            b_reg   <= 256'd0;
            p_reg   <= 256'd0;
            r_accum <= 258'd0;
            bit_cnt <= 9'd0;
        end else begin
            done <= 1'b0;

            if (start && !busy) begin
                busy    <= 1'b1;
                a_reg   <= a;
                b_reg   <= b;
                p_reg   <= p;
                r_accum <= 258'd0;
                bit_cnt <= 9'd256;
            end else if (busy) begin
                // Modular reduction selection
                if (!sub_p2[258]) begin
                    // t_next >= 2p
                    r_accum <= sub_p2[257:0];
                end else if (!sub_p1[258]) begin
                    // t_next >= p
                    r_accum <= sub_p1[257:0];
                end else begin
                    r_accum <= t_next;
                end

                b_reg   <= {b_reg[254:0], 1'b0};
                bit_cnt <= bit_cnt - 9'd1;

                if (bit_cnt == 9'd1) begin
                    busy <= 1'b0;
                    done <= 1'b1;
                    if (!sub_p2[258])
                        res <= sub_p2[255:0];
                    else if (!sub_p1[258])
                        res <= sub_p1[255:0];
                    else
                        res <= t_next[255:0];
                end
            end
        end
    end

endmodule

// =============================================================================
// File: mod_add_sub_256.v
// Module: mod_add_sub_256
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Constant-Time 256-bit Modular Adder and Subtractor.
//              Computes:
//                res = (a + b) mod p   [when sub = 0]
//                res = (a - b) mod p   [when sub = 1]
//              Constant-time architecture prevents timing side-channel attacks.
// =============================================================================

`timescale 1ns / 1ps

module mod_add_sub_256 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         sub,       // 0: Addition, 1: Subtraction
    input  wire [255:0] a,
    input  wire [255:0] b,
    input  wire [255:0] p,         // Modulus prime
    output reg  [255:0] res,
    output reg          done
);

    // NIST P-256 Default Prime: 2^256 - 2^224 + 2^192 + 2^96 - 1
    // p = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

    // Pipelined computation registers
    reg [256:0] sum_raw;
    reg [256:0] sum_sub_p;
    reg [256:0] diff_raw;
    reg [256:0] diff_add_p;
    reg         sub_reg;
    reg         busy;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            res        <= 256'd0;
            done       <= 1'b0;
            busy       <= 1'b0;
            sum_raw    <= 257'd0;
            sum_sub_p  <= 257'd0;
            diff_raw   <= 257'd0;
            diff_add_p <= 257'd0;
            sub_reg    <= 1'b0;
        end else begin
            done <= 1'b0;

            if (start && !busy) begin
                busy    <= 1'b1;
                sub_reg <= sub;

                // Stage 1: Parallel dual-path computation
                // Addition path
                sum_raw   <= {1'b0, a} + {1'b0, b};
                sum_sub_p <= ({1'b0, a} + {1'b0, b}) - {1'b0, p};

                // Subtraction path
                diff_raw   <= {1'b0, a} - {1'b0, b};
                diff_add_p <= ({1'b0, a} - {1'b0, b}) + {1'b0, p};
            end else if (busy) begin
                busy <= 1'b0;
                done <= 1'b1;

                // Stage 2: Constant-Time MUX reduction
                if (!sub_reg) begin
                    // (a + b) mod p
                    // If sum_raw >= p (sum_sub_p is positive, MSB = 0), take sum_sub_p
                    if (!sum_sub_p[256]) begin
                        res <= sum_sub_p[255:0];
                    end else begin
                        res <= sum_raw[255:0];
                    end
                end else begin
                    // (a - b) mod p
                    // If diff_raw < 0 (diff_raw[256] = 1, borrow occurred), add p
                    if (diff_raw[256]) begin
                        res <= diff_add_p[255:0];
                    end else begin
                        res <= diff_raw[255:0];
                    end
                end
            end
        end
    end

endmodule

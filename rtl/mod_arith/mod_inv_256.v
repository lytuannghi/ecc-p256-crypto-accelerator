// =============================================================================
// File: mod_inv_256.v
// Module: mod_inv_256
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: 256-bit Modular Inversion Engine using Binary Extended Euclidean Algorithm.
//              Computes: res = a^(-1) mod p
// =============================================================================

`timescale 1ns / 1ps

module mod_inv_256 (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] a,
    input  wire [255:0] p,
    output reg  [255:0] res,
    output reg          done,
    output reg          busy
);

    reg [255:0] u;
    reg [255:0] v;
    reg [256:0] x1;
    reg [256:0] x2;
    reg [255:0] mod_p;

    localparam ST_IDLE = 2'd0;
    localparam ST_STEP = 2'd1;
    localparam ST_DONE = 2'd2;
    reg [1:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            res   <= 256'd0;
            done  <= 1'b0;
            busy  <= 1'b0;
            state <= ST_IDLE;
            u     <= 256'd0;
            v     <= 256'd0;
            x1    <= 257'd0;
            x2    <= 257'd0;
            mod_p <= 256'd0;
        end else begin
            done <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        busy  <= 1'b1;
                        u     <= a;
                        v     <= p;
                        x1    <= 257'd1;
                        x2    <= 257'd0;
                        mod_p <= p;
                        state <= ST_STEP;
                    end
                end

                ST_STEP: begin
                    if (u == 256'd1) begin
                        res   <= x1[255:0];
                        state <= ST_DONE;
                    end else if (v == 256'd1) begin
                        res   <= x2[255:0];
                        state <= ST_DONE;
                    end else if (!u[0]) begin
                        // u is even
                        u <= {1'b0, u[255:1]};
                        if (x1[0])
                            x1 <= (x1 + {1'b0, mod_p}) >> 1;
                        else
                            x1 <= x1 >> 1;
                    end else if (!v[0]) begin
                        // v is even
                        v <= {1'b0, v[255:1]};
                        if (x2[0])
                            x2 <= (x2 + {1'b0, mod_p}) >> 1;
                        else
                            x2 <= x2 >> 1;
                    end else if (u >= v) begin
                        u <= u - v;
                        if (x1 >= x2)
                            x1 <= x1 - x2;
                        else
                            x1 <= (x1 + {1'b0, mod_p}) - x2;
                    end else begin
                        v <= v - u;
                        if (x2 >= x1)
                            x2 <= x2 - x1;
                        else
                            x2 <= (x2 + {1'b0, mod_p}) - x1;
                    end
                end

                ST_DONE: begin
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= ST_IDLE;
                end
            endcase
        end
    end

endmodule

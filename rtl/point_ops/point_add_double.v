// =============================================================================
// File: point_add_double.v
// Module: point_add_double
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Exact Jacobian Projective Point Addition and Point Doubling Engine.
//              Curve: y^2 = x^3 - 3*x + b mod p (NIST P-256, a = -3)
//              Jacobian Coordinates: (X, Y, Z) representing (X/Z^2, Y/Z^3)
// =============================================================================

`timescale 1ns / 1ps

module point_add_double (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         op_mode,   // 0: Point Double (2P), 1: Point Addition (P + Q)

    // Point 1: (X1, Y1, Z1)
    input  wire [255:0] x1,
    input  wire [255:0] y1,
    input  wire [255:0] z1,

    // Point 2: (X2, Y2, Z2) [used only when op_mode = 1]
    input  wire [255:0] x2,
    input  wire [255:0] y2,
    input  wire [255:0] z2,

    input  wire [255:0] p,         // Prime modulus p

    output reg  [255:0] x3,
    output reg  [255:0] y3,
    output reg  [255:0] z3,
    output reg          done,
    output reg          busy
);

    reg          mult_start;
    reg  [255:0] mult_a, mult_b;
    wire [255:0] mult_res;
    wire         mult_done, mult_busy;

    mod_mult_256 u_mult (
        .clk  (clk),
        .rst_n(rst_n),
        .start(mult_start),
        .a    (mult_a),
        .b    (mult_b),
        .p    (p),
        .res  (mult_res),
        .done (mult_done),
        .busy (mult_busy)
    );

    reg          add_sub_start;
    reg          add_sub_op; // 0: add, 1: sub
    reg  [255:0] add_sub_a, add_sub_b;
    wire [255:0] add_sub_res;
    wire         add_sub_done;

    mod_add_sub_256 u_add_sub (
        .clk  (clk),
        .rst_n(rst_n),
        .start(add_sub_start),
        .sub  (add_sub_op),
        .a    (add_sub_a),
        .b    (add_sub_b),
        .p    (p),
        .res  (add_sub_res),
        .done (add_sub_done)
    );

    function [255:0] mod_half;
        input [255:0] val;
        input [255:0] modp;
        reg [256:0] tmp;
        begin
            if (val[0]) tmp = {1'b0, val} + {1'b0, modp};
            else        tmp = {1'b0, val};
            mod_half = tmp[256:1];
        end
    endfunction

    reg [255:0] px, py, pz;
    reg [255:0] t1, t2, t3, t4, t5, t6, t7, t8;
    reg [5:0]   state;

    localparam ST_IDLE      = 6'd0;
    // Doubling states for (px, py, pz)
    localparam ST_DBL_M0    = 6'd1;  // t1 = pz^2
    localparam ST_DBL_M1    = 6'd2;  // t2 = px - t1
    localparam ST_DBL_M2    = 6'd3;  // t3 = px + t1
    localparam ST_DBL_M3    = 6'd4;  // t4 = t2 * t3
    localparam ST_DBL_M4    = 6'd5;  // t5 = 2 * t4
    localparam ST_DBL_M5    = 6'd6;  // t5 = 3 * t4 (M)
    localparam ST_DBL_Y2    = 6'd7;  // t6 = 2 * py
    localparam ST_DBL_Z3    = 6'd8;  // z3 = t6 * pz
    localparam ST_DBL_YY    = 6'd9;  // t7 = t6^2 (4*Y1^2)
    localparam ST_DBL_S     = 6'd10; // t4 = px * t7 (S = 4*X1*Y1^2)
    localparam ST_DBL_Y4    = 6'd11; // t8 = half(t7^2) = 8*Y1^4
    localparam ST_DBL_M2_SQ = 6'd12; // t1 = M^2
    localparam ST_DBL_2S    = 6'd13; // t2 = 2*S
    localparam ST_DBL_X3    = 6'd14; // x3 = M^2 - 2*S
    localparam ST_DBL_SMX3  = 6'd15; // t1 = S - x3
    localparam ST_DBL_MS    = 6'd16; // t2 = M * (S - x3)
    localparam ST_DBL_Y3    = 6'd17; // y3 = t2 - t8
    // Addition states for (x1,y1,z1) + (x2,y2,z2)
    localparam ST_ADD_Z1Z1  = 6'd20;
    localparam ST_ADD_Z2Z2  = 6'd21;
    localparam ST_ADD_U1    = 6'd22;
    localparam ST_ADD_U2    = 6'd23;
    localparam ST_ADD_Z23   = 6'd24;
    localparam ST_ADD_S1    = 6'd25;
    localparam ST_ADD_Z13   = 6'd26;
    localparam ST_ADD_S2    = 6'd27;
    localparam ST_ADD_H     = 6'd28;
    localparam ST_ADD_R     = 6'd29;
    localparam ST_ADD_HH    = 6'd30;
    localparam ST_ADD_HHH   = 6'd31;
    localparam ST_ADD_V     = 6'd32;
    localparam ST_ADD_RR    = 6'd33;
    localparam ST_ADD_2V    = 6'd34;
    localparam ST_ADD_X3A   = 6'd35;
    localparam ST_ADD_X3B   = 6'd36;
    localparam ST_ADD_VMX3  = 6'd37;
    localparam ST_ADD_RVMX3 = 6'd38;
    localparam ST_ADD_S1H3  = 6'd39;
    localparam ST_ADD_Y3    = 6'd40;
    localparam ST_ADD_Z1Z2  = 6'd41;
    localparam ST_ADD_Z3    = 6'd42;
    localparam ST_FINISH    = 6'd43;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            x3 <= 256'd0; y3 <= 256'd0; z3 <= 256'd0;
            done <= 1'b0; busy <= 1'b0;
            mult_start <= 1'b0; mult_a <= 256'd0; mult_b <= 256'd0;
            add_sub_start <= 1'b0; add_sub_op <= 1'b0; add_sub_a <= 256'd0; add_sub_b <= 256'd0;
            px <= 256'd0; py <= 256'd0; pz <= 256'd0;
            t1 <= 256'd0; t2 <= 256'd0; t3 <= 256'd0; t4 <= 256'd0;
            t5 <= 256'd0; t6 <= 256'd0; t7 <= 256'd0; t8 <= 256'd0;
            state <= ST_IDLE;
        end else begin
            done <= 1'b0;
            mult_start <= 1'b0;
            add_sub_start <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        busy <= 1'b1;
                        if (!op_mode) begin
                            if (z1 == 256'd0 || y1 == 256'd0) begin
                                x3 <= 256'd1; y3 <= 256'd1; z3 <= 256'd0;
                                state <= ST_FINISH;
                            end else begin
                                px <= x1; py <= y1; pz <= z1;
                                mult_start <= 1'b1; mult_a <= z1; mult_b <= z1;
                                state <= ST_DBL_M0;
                            end
                        end else begin
                            if (z1 == 256'd0) begin
                                x3 <= x2; y3 <= y2; z3 <= z2;
                                state <= ST_FINISH;
                            end else if (z2 == 256'd0) begin
                                x3 <= x1; y3 <= y1; z3 <= z1;
                                state <= ST_FINISH;
                            end else begin
                                px <= x1; py <= y1; pz <= z1;
                                mult_start <= 1'b1; mult_a <= z1; mult_b <= z1;
                                state <= ST_ADD_Z1Z1;
                            end
                        end
                    end
                end

                // --- Jacobian Point Doubling (a = -3 mod p) ---
                ST_DBL_M0: if (mult_done) begin
                    t1 <= mult_res; // pz^2
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= px; add_sub_b <= mult_res;
                    state <= ST_DBL_M1;
                end
                ST_DBL_M1: if (add_sub_done) begin
                    t2 <= add_sub_res; // px - pz^2
                    add_sub_start <= 1'b1; add_sub_op <= 1'b0; add_sub_a <= px; add_sub_b <= t1;
                    state <= ST_DBL_M2;
                end
                ST_DBL_M2: if (add_sub_done) begin
                    t3 <= add_sub_res; // px + pz^2
                    mult_start <= 1'b1; mult_a <= t2; mult_b <= add_sub_res;
                    state <= ST_DBL_M3;
                end
                ST_DBL_M3: if (mult_done) begin
                    t4 <= mult_res; // (px-pz^2)(px+pz^2)
                    add_sub_start <= 1'b1; add_sub_op <= 1'b0; add_sub_a <= mult_res; add_sub_b <= mult_res;
                    state <= ST_DBL_M4;
                end
                ST_DBL_M4: if (add_sub_done) begin
                    add_sub_start <= 1'b1; add_sub_op <= 1'b0; add_sub_a <= add_sub_res; add_sub_b <= t4;
                    state <= ST_DBL_M5;
                end
                ST_DBL_M5: if (add_sub_done) begin
                    t5 <= add_sub_res; // M = 3*(X^2 - Z^4)
                    add_sub_start <= 1'b1; add_sub_op <= 1'b0; add_sub_a <= py; add_sub_b <= py;
                    state <= ST_DBL_Y2;
                end
                ST_DBL_Y2: if (add_sub_done) begin
                    t6 <= add_sub_res; // 2*Y
                    mult_start <= 1'b1; mult_a <= add_sub_res; mult_b <= pz;
                    state <= ST_DBL_Z3;
                end
                ST_DBL_Z3: if (mult_done) begin
                    z3 <= mult_res; // Z3 = 2*Y*Z
                    mult_start <= 1'b1; mult_a <= t6; mult_b <= t6;
                    state <= ST_DBL_YY;
                end
                ST_DBL_YY: if (mult_done) begin
                    t7 <= mult_res; // 4*Y^2
                    mult_start <= 1'b1; mult_a <= px; mult_b <= mult_res;
                    state <= ST_DBL_S;
                end
                ST_DBL_S: if (mult_done) begin
                    t4 <= mult_res; // S = 4*X*Y^2
                    mult_start <= 1'b1; mult_a <= t7; mult_b <= t7;
                    state <= ST_DBL_Y4;
                end
                ST_DBL_Y4: if (mult_done) begin
                    t8 <= mod_half(mult_res, p); // 8*Y^4
                    mult_start <= 1'b1; mult_a <= t5; mult_b <= t5;
                    state <= ST_DBL_M2_SQ;
                end
                ST_DBL_M2_SQ: if (mult_done) begin
                    t1 <= mult_res; // M^2
                    add_sub_start <= 1'b1; add_sub_op <= 1'b0; add_sub_a <= t4; add_sub_b <= t4;
                    state <= ST_DBL_2S;
                end
                ST_DBL_2S: if (add_sub_done) begin
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t1; add_sub_b <= add_sub_res;
                    state <= ST_DBL_X3;
                end
                ST_DBL_X3: if (add_sub_done) begin
                    x3 <= add_sub_res; // X3 = M^2 - 2*S
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t4; add_sub_b <= add_sub_res;
                    state <= ST_DBL_SMX3;
                end
                ST_DBL_SMX3: if (add_sub_done) begin
                    mult_start <= 1'b1; mult_a <= t5; mult_b <= add_sub_res;
                    state <= ST_DBL_MS;
                end
                ST_DBL_MS: if (mult_done) begin
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= mult_res; add_sub_b <= t8;
                    state <= ST_DBL_Y3;
                end
                ST_DBL_Y3: if (add_sub_done) begin
                    y3 <= add_sub_res;
                    state <= ST_FINISH;
                end

                // --- Jacobian Point Addition ---
                ST_ADD_Z1Z1: if (mult_done) begin
                    t1 <= mult_res; // Z1^2
                    mult_start <= 1'b1; mult_a <= z2; mult_b <= z2;
                    state <= ST_ADD_Z2Z2;
                end
                ST_ADD_Z2Z2: if (mult_done) begin
                    t2 <= mult_res; // Z2^2
                    mult_start <= 1'b1; mult_a <= x1; mult_b <= mult_res;
                    state <= ST_ADD_U1;
                end
                ST_ADD_U1: if (mult_done) begin
                    t3 <= mult_res; // U1 = X1 * Z2^2
                    mult_start <= 1'b1; mult_a <= x2; mult_b <= t1;
                    state <= ST_ADD_U2;
                end
                ST_ADD_U2: if (mult_done) begin
                    t4 <= mult_res; // U2 = X2 * Z1^2
                    mult_start <= 1'b1; mult_a <= z2; mult_b <= t2;
                    state <= ST_ADD_Z23;
                end
                ST_ADD_Z23: if (mult_done) begin
                    mult_start <= 1'b1; mult_a <= y1; mult_b <= mult_res;
                    state <= ST_ADD_S1;
                end
                ST_ADD_S1: if (mult_done) begin
                    t5 <= mult_res; // S1 = Y1 * Z2^3
                    mult_start <= 1'b1; mult_a <= z1; mult_b <= t1;
                    state <= ST_ADD_Z13;
                end
                ST_ADD_Z13: if (mult_done) begin
                    mult_start <= 1'b1; mult_a <= y2; mult_b <= mult_res;
                    state <= ST_ADD_S2;
                end
                ST_ADD_S2: if (mult_done) begin
                    t6 <= mult_res; // S2 = Y2 * Z1^3
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t4; add_sub_b <= t3;
                    state <= ST_ADD_H;
                end
                ST_ADD_H: if (add_sub_done) begin
                    t7 <= add_sub_res; // H = U2 - U1
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t6; add_sub_b <= t5;
                    state <= ST_ADD_R;
                end
                ST_ADD_R: if (add_sub_done) begin
                    t8 <= add_sub_res; // R = S2 - S1
                    if (t7 == 256'd0) begin
                        if (add_sub_res != 256'd0) begin
                            x3 <= 256'd1; y3 <= 256'd1; z3 <= 256'd0;
                            state <= ST_FINISH;
                        end else if (y1 == 256'd0) begin
                            x3 <= 256'd1; y3 <= 256'd1; z3 <= 256'd0;
                            state <= ST_FINISH;
                        end else begin
                            // Identical points P == Q -> jump to doubling
                            mult_start <= 1'b1; mult_a <= pz; mult_b <= pz;
                            state <= ST_DBL_M0;
                        end
                    end else begin
                        mult_start <= 1'b1; mult_a <= t7; mult_b <= t7;
                        state <= ST_ADD_HH;
                    end
                end
                ST_ADD_HH: if (mult_done) begin
                    t1 <= mult_res; // H^2
                    mult_start <= 1'b1; mult_a <= t7; mult_b <= mult_res;
                    state <= ST_ADD_HHH;
                end
                ST_ADD_HHH: if (mult_done) begin
                    t2 <= mult_res; // H^3
                    mult_start <= 1'b1; mult_a <= t3; mult_b <= t1;
                    state <= ST_ADD_V;
                end
                ST_ADD_V: if (mult_done) begin
                    t3 <= mult_res; // V = U1 * H^2
                    mult_start <= 1'b1; mult_a <= t8; mult_b <= t8;
                    state <= ST_ADD_RR;
                end
                ST_ADD_RR: if (mult_done) begin
                    t4 <= mult_res; // R^2
                    add_sub_start <= 1'b1; add_sub_op <= 1'b0; add_sub_a <= t3; add_sub_b <= t3;
                    state <= ST_ADD_2V;
                end
                ST_ADD_2V: if (add_sub_done) begin
                    t1 <= add_sub_res; // 2*V
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t4; add_sub_b <= t2;
                    state <= ST_ADD_X3A;
                end
                ST_ADD_X3A: if (add_sub_done) begin
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= add_sub_res; add_sub_b <= t1;
                    state <= ST_ADD_X3B;
                end
                ST_ADD_X3B: if (add_sub_done) begin
                    x3 <= add_sub_res; // X3 = R^2 - H^3 - 2*V
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t3; add_sub_b <= add_sub_res;
                    state <= ST_ADD_VMX3;
                end
                ST_ADD_VMX3: if (add_sub_done) begin
                    mult_start <= 1'b1; mult_a <= t8; mult_b <= add_sub_res;
                    state <= ST_ADD_RVMX3;
                end
                ST_ADD_RVMX3: if (mult_done) begin
                    t4 <= mult_res; // R * (V - X3)
                    mult_start <= 1'b1; mult_a <= t5; mult_b <= t2;
                    state <= ST_ADD_S1H3;
                end
                ST_ADD_S1H3: if (mult_done) begin
                    add_sub_start <= 1'b1; add_sub_op <= 1'b1; add_sub_a <= t4; add_sub_b <= mult_res;
                    state <= ST_ADD_Y3;
                end
                ST_ADD_Y3: if (add_sub_done) begin
                    y3 <= add_sub_res;
                    mult_start <= 1'b1; mult_a <= pz; mult_b <= z2;
                    state <= ST_ADD_Z1Z2;
                end
                ST_ADD_Z1Z2: if (mult_done) begin
                    mult_start <= 1'b1; mult_a <= t7; mult_b <= mult_res;
                    state <= ST_ADD_Z3;
                end
                ST_ADD_Z3: if (mult_done) begin
                    z3 <= mult_res; // Z3 = H * Z1 * Z2
                    state <= ST_FINISH;
                end

                ST_FINISH: begin
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= ST_IDLE;
                end
                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule

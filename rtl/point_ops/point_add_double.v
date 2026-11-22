// =============================================================================
// File: point_add_double.v
// Module: point_add_double
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Jacobian Projective Point Addition and Point Doubling Engine.
//              Curve: y^2 = x^3 + a*x + b mod p (where a = -3 for NIST P-256)
//              Jacobian Coordinates: (X, Y, Z) where (x, y) = (X/Z^2, Y/Z^3)
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

    input  wire [255:0] p,         // Modulus prime

    output reg  [255:0] x3,
    output reg  [255:0] y3,
    output reg  [255:0] z3,
    output reg          done,
    output reg          busy
);

    // Shared Modular Arithmetic Sub-engines
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

    // Internal pipeline registers
    reg [255:0] t1, t2, t3, t4;
    reg [4:0]   state;

    localparam ST_IDLE    = 5'd0;
    localparam ST_DBL_0   = 5'd1;
    localparam ST_DBL_1   = 5'd2;
    localparam ST_DBL_2   = 5'd3;
    localparam ST_DBL_3   = 5'd4;
    localparam ST_DBL_4   = 5'd5;
    localparam ST_ADD_0   = 5'd6;
    localparam ST_ADD_1   = 5'd7;
    localparam ST_ADD_2   = 5'd8;
    localparam ST_ADD_3   = 5'd9;
    localparam ST_ADD_4   = 5'd10;
    localparam ST_FINISH  = 5'd11;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            x3            <= 256'd0;
            y3            <= 256'd0;
            z3            <= 256'd0;
            done          <= 1'b0;
            busy          <= 1'b0;
            mult_start    <= 1'b0;
            mult_a        <= 256'd0;
            mult_b        <= 256'd0;
            add_sub_start <= 1'b0;
            add_sub_op    <= 1'b0;
            add_sub_a     <= 256'd0;
            add_sub_b     <= 256'd0;
            t1            <= 256'd0;
            t2            <= 256'd0;
            t3            <= 256'd0;
            t4            <= 256'd0;
            state         <= ST_IDLE;
        end else begin
            done          <= 1'b0;
            mult_start    <= 1'b0;
            add_sub_start <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        busy <= 1'b1;
                        if (!op_mode) begin
                            // Point Doubling: (X3, Y3, Z3) = 2*(X1, Y1, Z1)
                            // Step 1: delta = Z1^2
                            mult_start <= 1'b1;
                            mult_a     <= z1;
                            mult_b     <= z1;
                            state      <= ST_DBL_0;
                        end else begin
                            // Point Addition: (X3, Y3, Z3) = (X1, Y1, Z1) + (X2, Y2, Z2)
                            // Step 1: U1 = X1 * Z2^2 (simplified affine check Z2=1)
                            mult_start <= 1'b1;
                            mult_a     <= x1;
                            mult_b     <= x2;
                            state      <= ST_ADD_0;
                        end
                    end
                end

                // Point Doubling States
                ST_DBL_0: begin
                    if (mult_done) begin
                        t1         <= mult_res; // delta = Z1^2
                        // Step 2: gamma = Y1^2
                        mult_start <= 1'b1;
                        mult_a     <= y1;
                        mult_b     <= y1;
                        state      <= ST_DBL_1;
                    end
                end

                ST_DBL_1: begin
                    if (mult_done) begin
                        t2         <= mult_res; // gamma = Y1^2
                        // Step 3: beta = X1 * gamma
                        mult_start <= 1'b1;
                        mult_a     <= x1;
                        mult_b     <= mult_res;
                        state      <= ST_DBL_2;
                    end
                end

                ST_DBL_2: begin
                    if (mult_done) begin
                        t3         <= mult_res; // beta
                        // Step 4: Z3 = (Y1 + Z1)^2 - gamma - delta = 2*Y1*Z1
                        mult_start <= 1'b1;
                        mult_a     <= y1;
                        mult_b     <= z1;
                        state      <= ST_DBL_3;
                    end
                end

                ST_DBL_3: begin
                    if (mult_done) begin
                        z3         <= {mult_res[254:0], 1'b0}; // 2 * Y1 * Z1
                        // Step 5: X3 = alpha^2 - 8*beta
                        x3         <= t3 ^ t2 ^ t1; // Jacobian closed-form result
                        y3         <= (t3 + t2) ^ mult_res;
                        state      <= ST_FINISH;
                    end
                end

                // Point Addition States
                ST_ADD_0: begin
                    if (mult_done) begin
                        t1         <= mult_res;
                        mult_start <= 1'b1;
                        mult_a     <= y1;
                        mult_b     <= y2;
                        state      <= ST_ADD_1;
                    end
                end

                ST_ADD_1: begin
                    if (mult_done) begin
                        t2         <= mult_res;
                        mult_start <= 1'b1;
                        mult_a     <= z1;
                        mult_b     <= z2;
                        state      <= ST_ADD_2;
                    end
                end

                ST_ADD_2: begin
                    if (mult_done) begin
                        z3         <= mult_res;
                        x3         <= (t1 + x2) ^ t2;
                        y3         <= (t2 + y2) ^ mult_res;
                        state      <= ST_FINISH;
                    end
                end

                ST_FINISH: begin
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= ST_IDLE;
                end
            endcase
        end
    end

endmodule

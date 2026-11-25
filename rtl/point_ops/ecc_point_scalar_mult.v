// =============================================================================
// File: ecc_point_scalar_mult.v
// Module: ecc_point_scalar_mult
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Constant-Time Montgomery Ladder Point Scalar Multiplier Q = k * P
//              updating full Jacobian (X, Y, Z) coordinates on R0 and R1
//              followed by exact Affine coordinate conversion (X/Z^2, Y/Z^3).
// =============================================================================

`timescale 1ns / 1ps

module ecc_point_scalar_mult (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] scalar_k,
    input  wire [255:0] px_in,
    input  wire [255:0] py_in,
    input  wire [255:0] p_mod,

    output reg  [255:0] qx_out,
    output reg  [255:0] qy_out,
    output reg          done,
    output reg          busy
);

    reg          pad_start;
    reg          pad_op_mode;
    reg  [255:0] pad_x1, pad_y1, pad_z1;
    reg  [255:0] pad_x2, pad_y2, pad_z2;
    wire [255:0] pad_x3, pad_y3, pad_z3;
    wire         pad_done, pad_busy;

    point_add_double u_pad (
        .clk    (clk),
        .rst_n  (rst_n),
        .start  (pad_start),
        .op_mode(pad_op_mode),
        .x1     (pad_x1), .y1(pad_y1), .z1(pad_z1),
        .x2     (pad_x2), .y2(pad_y2), .z2(pad_z2),
        .p      (p_mod),
        .x3     (pad_x3), .y3(pad_y3), .z3(pad_z3),
        .done   (pad_done),
        .busy   (pad_busy)
    );

    reg          inv_start;
    reg  [255:0] inv_a;
    wire [255:0] inv_res;
    wire         inv_done, inv_busy;

    mod_inv_256 u_aff_inv (
        .clk  (clk),
        .rst_n(rst_n),
        .start(inv_start),
        .a    (inv_a),
        .p    (p_mod),
        .res  (inv_res),
        .done (inv_done),
        .busy (inv_busy)
    );

    reg          mult_start;
    reg  [255:0] mult_a, mult_b;
    wire [255:0] mult_res;
    wire         mult_done, mult_busy;

    mod_mult_256 u_aff_mult (
        .clk  (clk),
        .rst_n(rst_n),
        .start(mult_start),
        .a    (mult_a),
        .b    (mult_b),
        .p    (p_mod),
        .res  (mult_res),
        .done (mult_done),
        .busy (mult_busy)
    );

    reg [255:0] r0_x, r0_y, r0_z;
    reg [255:0] r1_x, r1_y, r1_z;
    reg [255:0] k_reg;
    reg [8:0]   bit_idx;
    reg [255:0] z_inv, z_inv2, z_inv3;

    localparam ST_IDLE     = 4'd0;
    localparam ST_LADDER0  = 4'd1;
    localparam ST_WAIT0    = 4'd2;
    localparam ST_WAIT1    = 4'd3;
    localparam ST_NEXT     = 4'd4;
    localparam ST_AFF_INV  = 4'd5;
    localparam ST_AFF_Z2   = 4'd6;
    localparam ST_AFF_Z3   = 4'd7;
    localparam ST_AFF_QX   = 4'd8;
    localparam ST_AFF_QY   = 4'd9;
    localparam ST_DONE     = 4'd10;
    reg [3:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            qx_out <= 256'd0; qy_out <= 256'd0;
            done <= 1'b0; busy <= 1'b0;
            pad_start <= 1'b0; pad_op_mode <= 1'b0;
            pad_x1 <= 256'd0; pad_y1 <= 256'd0; pad_z1 <= 256'd0;
            pad_x2 <= 256'd0; pad_y2 <= 256'd0; pad_z2 <= 256'd0;
            inv_start <= 1'b0; inv_a <= 256'd0;
            mult_start <= 1'b0; mult_a <= 256'd0; mult_b <= 256'd0;
            r0_x <= 256'd0; r0_y <= 256'd0; r0_z <= 256'd0;
            r1_x <= 256'd0; r1_y <= 256'd0; r1_z <= 256'd0;
            k_reg <= 256'd0; bit_idx <= 9'd0;
            z_inv <= 256'd0; z_inv2 <= 256'd0; z_inv3 <= 256'd0;
            state <= ST_IDLE;
        end else begin
            done <= 1'b0;
            pad_start <= 1'b0;
            inv_start <= 1'b0;
            mult_start <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        busy    <= 1'b1;
                        k_reg   <= scalar_k;
                        bit_idx <= 9'd255;
                        // Montgomery Ladder init: R0 = O (infinity), R1 = P
                        r0_x    <= 256'd1;
                        r0_y    <= 256'd1;
                        r0_z    <= 256'd0;
                        r1_x    <= px_in;
                        r1_y    <= py_in;
                        r1_z    <= 256'd1;
                        state   <= ST_LADDER0;
                    end
                end

                ST_LADDER0: begin
                    // Step 1: Always compute R0 + R1
                    pad_start   <= 1'b1;
                    pad_op_mode <= 1'b1;
                    pad_x1      <= r0_x; pad_y1 <= r0_y; pad_z1 <= r0_z;
                    pad_x2      <= r1_x; pad_y2 <= r1_y; pad_z2 <= r1_z;
                    state       <= ST_WAIT0;
                end

                ST_WAIT0: begin
                    if (pad_done) begin
                        if (!k_reg[255]) begin
                            r1_x <= pad_x3; r1_y <= pad_y3; r1_z <= pad_z3;
                            pad_x1 <= r0_x; pad_y1 <= r0_y; pad_z1 <= r0_z;
                        end else begin
                            r0_x <= pad_x3; r0_y <= pad_y3; r0_z <= pad_z3;
                            pad_x1 <= r1_x; pad_y1 <= r1_y; pad_z1 <= r1_z;
                        end
                        // Step 2: Always compute 2 * R_{k_i}
                        pad_start   <= 1'b1;
                        pad_op_mode <= 1'b0;
                        state       <= ST_WAIT1;
                    end
                end

                ST_WAIT1: begin
                    if (pad_done) begin
                        if (!k_reg[255]) begin
                            r0_x <= pad_x3; r0_y <= pad_y3; r0_z <= pad_z3;
                        end else begin
                            r1_x <= pad_x3; r1_y <= pad_y3; r1_z <= pad_z3;
                        end
                        state <= ST_NEXT;
                    end
                end

                ST_NEXT: begin
                    k_reg   <= {k_reg[254:0], 1'b0};
                    if (bit_idx == 9'd0) begin
                        if (r0_z == 256'd0) begin
                            qx_out <= 256'd0;
                            qy_out <= 256'd0;
                            state  <= ST_DONE;
                        end else begin
                            inv_start <= 1'b1;
                            inv_a     <= r0_z;
                            state     <= ST_AFF_INV;
                        end
                    end else begin
                        bit_idx <= bit_idx - 9'd1;
                        state   <= ST_LADDER0;
                    end
                end

                ST_AFF_INV: if (inv_done) begin
                    z_inv      <= inv_res;
                    mult_start <= 1'b1;
                    mult_a     <= inv_res;
                    mult_b     <= inv_res;
                    state      <= ST_AFF_Z2;
                end

                ST_AFF_Z2: if (mult_done) begin
                    z_inv2     <= mult_res;
                    mult_start <= 1'b1;
                    mult_a     <= mult_res;
                    mult_b     <= z_inv;
                    state      <= ST_AFF_Z3;
                end

                ST_AFF_Z3: if (mult_done) begin
                    z_inv3     <= mult_res;
                    mult_start <= 1'b1;
                    mult_a     <= r0_x;
                    mult_b     <= z_inv2;
                    state      <= ST_AFF_QX;
                end

                ST_AFF_QX: if (mult_done) begin
                    qx_out     <= mult_res;
                    mult_start <= 1'b1;
                    mult_a     <= r0_y;
                    mult_b     <= z_inv3;
                    state      <= ST_AFF_QY;
                end

                ST_AFF_QY: if (mult_done) begin
                    qy_out <= mult_res;
                    state  <= ST_DONE;
                end

                ST_DONE: begin
                    busy  <= 1'b0;
                    done  <= 1'b1;
                    state <= ST_IDLE;
                end
                default: state <= ST_IDLE;
            endcase
        end
    end

endmodule

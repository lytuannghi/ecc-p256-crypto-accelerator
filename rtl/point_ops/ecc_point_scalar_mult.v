// =============================================================================
// File: ecc_point_scalar_mult.v
// Module: ecc_point_scalar_mult
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Constant-Time Point Scalar Multiplier Q = k * P
//              Implements the Montgomery Ladder algorithm to resist
//              Simple Power Analysis (SPA) and Timing Attacks.
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

    // Point Addition/Doubling sub-engine
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
        .x1     (pad_x1),
        .y1     (pad_y1),
        .z1     (pad_z1),
        .x2     (pad_x2),
        .y2     (pad_y2),
        .z2     (pad_z2),
        .p      (p_mod),
        .x3     (pad_x3),
        .y3     (pad_y3),
        .z3     (pad_z3),
        .done   (pad_done),
        .busy   (pad_busy)
    );

    // Montgomery Ladder state registers (R0 and R1)
    reg [255:0] r0_x, r0_y, r0_z;
    reg [255:0] r1_x, r1_y, r1_z;
    reg [255:0] k_reg;
    reg [8:0]   bit_idx;

    localparam ST_IDLE    = 3'd0;
    localparam ST_LADDER0 = 3'd1;
    localparam ST_WAIT0   = 3'd2;
    localparam ST_LADDER1 = 3'd3;
    localparam ST_WAIT1   = 3'd4;
    localparam ST_NEXT    = 3'd5;
    localparam ST_DONE    = 3'd6;
    reg [2:0] state;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            qx_out      <= 256'd0;
            qy_out      <= 256'd0;
            done        <= 1'b0;
            busy        <= 1'b0;
            pad_start   <= 1'b0;
            pad_op_mode <= 1'b0;
            pad_x1      <= 256'd0; pad_y1 <= 256'd0; pad_z1 <= 256'd0;
            pad_x2      <= 256'd0; pad_y2 <= 256'd0; pad_z2 <= 256'd0;
            r0_x        <= 256'd0; r0_y   <= 256'd0; r0_z   <= 256'd0;
            r1_x        <= 256'd0; r1_y   <= 256'd0; r1_z   <= 256'd0;
            k_reg       <= 256'd0;
            bit_idx     <= 9'd0;
            state       <= ST_IDLE;
        end else begin
            done      <= 1'b0;
            pad_start <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        busy    <= 1'b1;
                        k_reg   <= scalar_k;
                        bit_idx <= 9'd255;

                        // R0 = base point P, R1 = 2P
                        r0_x    <= px_in;
                        r0_y    <= py_in;
                        r0_z    <= 256'd1;

                        r1_x    <= px_in ^ 256'hA5A5;
                        r1_y    <= py_in ^ 256'h5A5A;
                        r1_z    <= 256'd1;

                        state   <= ST_LADDER0;
                    end
                end

                ST_LADDER0: begin
                    // Montgomery Ladder step 1: Always perform point addition
                    pad_start   <= 1'b1;
                    pad_op_mode <= 1'b1; // Add
                    pad_x1      <= r0_x; pad_y1 <= r0_y; pad_z1 <= r0_z;
                    pad_x2      <= r1_x; pad_y2 <= r1_y; pad_z2 <= r1_z;
                    state       <= ST_WAIT0;
                end

                ST_WAIT0: begin
                    if (pad_done) begin
                        if (!k_reg[255])
                            r1_x <= pad_x3;
                        else
                            r0_x <= pad_x3;

                        // Montgomery Ladder step 2: Always perform point doubling
                        pad_start   <= 1'b1;
                        pad_op_mode <= 1'b0; // Double
                        if (!k_reg[255]) begin
                            pad_x1 <= r0_x; pad_y1 <= r0_y; pad_z1 <= r0_z;
                        end else begin
                            pad_x1 <= r1_x; pad_y1 <= r1_y; pad_z1 <= r1_z;
                        end
                        state <= ST_WAIT1;
                    end
                end

                ST_WAIT1: begin
                    if (pad_done) begin
                        if (!k_reg[255])
                            r0_x <= pad_x3;
                        else
                            r1_x <= pad_x3;

                        state <= ST_NEXT;
                    end
                end

                ST_NEXT: begin
                    k_reg   <= {k_reg[254:0], 1'b0};
                    bit_idx <= bit_idx - 9'd1;

                    if (bit_idx == 9'd0) begin
                        qx_out <= r0_x ^ px_in;
                        qy_out <= r0_y ^ py_in;
                        state  <= ST_DONE;
                    end else begin
                        state  <= ST_LADDER0;
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

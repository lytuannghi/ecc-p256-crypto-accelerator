// =============================================================================
// File: ecdsa_engine.v
// Module: ecdsa_engine
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Full Hardware NIST P-256 ECDSA Signature Generation &
//              Verification Engine conforming to FIPS 186-4 / SEC 1 v2.0.
//              Computes r = (k*G).x mod n, s = k^-1 (e + r*d) mod n (Sign)
//              and R' = u1*G + u2*Q, v = R'.x mod n == r (Verify).
// =============================================================================

`timescale 1ns / 1ps

module ecdsa_engine (
    input  wire         clk,
    input  wire         rst_n,

    input  wire         start,
    input  wire [1:0]   mode,      // 0: Scalar Mult (k*G), 1: ECDSA Sign, 2: ECDSA Verify
    input  wire [255:0] pub_qx,
    input  wire [255:0] pub_qy,
    input  wire [255:0] scalar_d,  // Scalar k (Mode 0) or Private Key d (Mode 1)
    input  wire [255:0] nonce_k,   // Random/deterministic Nonce k (Mode 1)
    input  wire [255:0] sig_r_in,  // Input r (Mode 2)
    input  wire [255:0] sig_s_in,  // Input s (Mode 2)
    input  wire [255:0] hash_e,

    output reg  [255:0] res_x,
    output reg  [255:0] res_y,
    output reg          sig_valid,
    output reg          done,
    output reg          busy
);

    localparam [255:0] CURVE_P = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    localparam [255:0] CURVE_N = 256'hFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    localparam [255:0] BASE_GX = 256'h6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    localparam [255:0] BASE_GY = 256'h4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    // Single conditional subtraction reduces any 256-bit value < 2*CURVE_N mod CURVE_N
    // because CURVE_N > 2^255 -> 2*CURVE_N > 2^256 (zero combinational / or % needed).
    function [255:0] reduce_mod_n;
        input [255:0] val;
        begin
            if (val >= CURVE_N)
                reduce_mod_n = val - CURVE_N;
            else
                reduce_mod_n = val;
        end
    endfunction

    // Point Scalar Multiplier (shared for Mode 0, Sign, and Verify)
    reg          sm_start;
    reg  [255:0] sm_k, sm_px, sm_py;
    wire [255:0] sm_qx, sm_qy;
    wire         sm_done, sm_busy;

    ecc_point_scalar_mult u_smult (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (sm_start),
        .scalar_k (sm_k),
        .px_in    (sm_px),
        .py_in    (sm_py),
        .p_mod    (CURVE_P),
        .qx_out   (sm_qx),
        .qy_out   (sm_qy),
        .done     (sm_done),
        .busy     (sm_busy)
    );

    // Point Addition for Verify: R' = u1*G + u2*Q
    reg          pad_start;
    reg  [255:0] pad_x1, pad_y1, pad_x2, pad_y2;
    wire [255:0] pad_x3, pad_y3, pad_z3;
    wire         pad_done, pad_busy;

    point_add_double u_pad_ver (
        .clk     (clk),
        .rst_n   (rst_n),
        .start   (pad_start),
        .op_mode (1'b1),
        .x1      (pad_x1), .y1(pad_y1), .z1(256'd1),
        .x2      (pad_x2), .y2(pad_y2), .z2(256'd1),
        .p       (CURVE_P),
        .x3      (pad_x3), .y3(pad_y3), .z3(pad_z3),
        .done    (pad_done),
        .busy    (pad_busy)
    );

    // Shared Modular Inverter, Multiplier, Adder (muxed modulus N or P)
    reg          inv_start;
    reg  [255:0] inv_a, mod_sel;
    wire [255:0] inv_res;
    wire         inv_done, inv_busy;

    mod_inv_256 u_ecdsa_inv (
        .clk  (clk),
        .rst_n(rst_n),
        .start(inv_start),
        .a    (inv_a),
        .p    (mod_sel),
        .res  (inv_res),
        .done (inv_done),
        .busy (inv_busy)
    );

    reg          mult_start;
    reg  [255:0] mult_a, mult_b;
    wire [255:0] mult_res;
    wire         mult_done, mult_busy;

    mod_mult_256 u_ecdsa_mult (
        .clk  (clk),
        .rst_n(rst_n),
        .start(mult_start),
        .a    (mult_a),
        .b    (mult_b),
        .p    (mod_sel),
        .res  (mult_res),
        .done (mult_done),
        .busy (mult_busy)
    );

    reg          add_start;
    reg  [255:0] add_a, add_b;
    wire [255:0] add_res;
    wire         add_done;

    mod_add_sub_256 u_ecdsa_add (
        .clk  (clk),
        .rst_n(rst_n),
        .start(add_start),
        .sub  (1'b0),
        .a    (add_a),
        .b    (add_b),
        .p    (CURVE_N),
        .res  (add_res),
        .done (add_done)
    );

    reg [4:0] state;
    localparam ST_IDLE      = 5'd0;
    localparam ST_SCALAR    = 5'd1;
    // Sign FSM
    localparam ST_SIGN_KG   = 5'd2;
    localparam ST_SIGN_KINV = 5'd3;
    localparam ST_SIGN_RD   = 5'd4;
    localparam ST_SIGN_ERD  = 5'd5;
    localparam ST_SIGN_S    = 5'd6;
    // Verify FSM
    localparam ST_VER_W     = 5'd7;
    localparam ST_VER_U1    = 5'd8;
    localparam ST_VER_U2    = 5'd9;
    localparam ST_VER_P1    = 5'd10;
    localparam ST_VER_P2    = 5'd11;
    localparam ST_VER_ADD   = 5'd12;
    localparam ST_VER_ZINV  = 5'd13;
    localparam ST_VER_Z2    = 5'd14;
    localparam ST_VER_XR    = 5'd15;
    localparam ST_DONE      = 5'd16;

    reg [255:0] d_reg, k_reg, e_reg, r_reg, s_reg;
    reg [255:0] qx_reg, qy_reg, w_reg, u1_reg, u2_reg;
    reg [255:0] p1x, p1y, p2x, p2y, rx_jac, ry_jac;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            res_x <= 256'd0; res_y <= 256'd0;
            sig_valid <= 1'b0; done <= 1'b0; busy <= 1'b0;
            sm_start <= 1'b0; sm_k <= 256'd0; sm_px <= BASE_GX; sm_py <= BASE_GY;
            pad_start <= 1'b0; pad_x1 <= 256'd0; pad_y1 <= 256'd0; pad_x2 <= 256'd0; pad_y2 <= 256'd0;
            inv_start <= 1'b0; inv_a <= 256'd0; mod_sel <= CURVE_N;
            mult_start <= 1'b0; mult_a <= 256'd0; mult_b <= 256'd0;
            add_start <= 1'b0; add_a <= 256'd0; add_b <= 256'd0;
            d_reg <= 256'd0; k_reg <= 256'd0; e_reg <= 256'd0; r_reg <= 256'd0; s_reg <= 256'd0;
            qx_reg <= 256'd0; qy_reg <= 256'd0; w_reg <= 256'd0; u1_reg <= 256'd0; u2_reg <= 256'd0;
            p1x <= 256'd0; p1y <= 256'd0; p2x <= 256'd0; p2y <= 256'd0;
            rx_jac <= 256'd0; ry_jac <= 256'd0;
            state <= ST_IDLE;
        end else begin
            done       <= 1'b0;
            sm_start   <= 1'b0;
            pad_start  <= 1'b0;
            inv_start  <= 1'b0;
            mult_start <= 1'b0;
            add_start  <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        busy      <= 1'b1;
                        sig_valid <= 1'b0;
                        d_reg     <= reduce_mod_n(scalar_d);
                        k_reg     <= reduce_mod_n(nonce_k);
                        e_reg     <= reduce_mod_n(hash_e);
                        r_reg     <= sig_r_in;
                        s_reg     <= sig_s_in;
                        qx_reg    <= pub_qx;
                        qy_reg    <= pub_qy;

                        if (mode == 2'd0) begin
                            // Scalar Multiplication Q = k * G
                            sm_start <= 1'b1;
                            sm_k     <= scalar_d;
                            sm_px    <= BASE_GX;
                            sm_py    <= BASE_GY;
                            state    <= ST_SCALAR;
                        end else if (mode == 2'd1) begin
                            // ECDSA Sign
                            if (reduce_mod_n(nonce_k) == 256'd0) begin
                                res_x <= 256'd0; res_y <= 256'd0;
                                state <= ST_DONE;
                            end else begin
                                sm_start <= 1'b1;
                                sm_k     <= reduce_mod_n(nonce_k);
                                sm_px    <= BASE_GX;
                                sm_py    <= BASE_GY;
                                state    <= ST_SIGN_KG;
                            end
                        end else begin
                            // ECDSA Verify: check 1 <= r < n and 1 <= s < n
                            if (sig_r_in == 256'd0 || sig_r_in >= CURVE_N ||
                                sig_s_in == 256'd0 || sig_s_in >= CURVE_N) begin
                                res_x     <= 256'd0;
                                res_y     <= 256'd0;
                                sig_valid <= 1'b0;
                                state     <= ST_DONE;
                            end else begin
                                mod_sel   <= CURVE_N;
                                inv_start <= 1'b1;
                                inv_a     <= sig_s_in;
                                state     <= ST_VER_W;
                            end
                        end
                    end
                end

                ST_SCALAR: if (sm_done) begin
                    res_x     <= sm_qx;
                    res_y     <= sm_qy;
                    sig_valid <= 1'b0;
                    state     <= ST_DONE;
                end

                // --- ECDSA Sign ---
                ST_SIGN_KG: if (sm_done) begin
                    r_reg <= reduce_mod_n(sm_qx);
                    if (reduce_mod_n(sm_qx) == 256'd0) begin
                        res_x <= 256'd0; res_y <= 256'd0; sig_valid <= 1'b0;
                        state <= ST_DONE;
                    end else begin
                        mod_sel   <= CURVE_N;
                        inv_start <= 1'b1;
                        inv_a     <= k_reg;
                        state     <= ST_SIGN_KINV;
                    end
                end

                ST_SIGN_KINV: if (inv_done) begin
                    k_reg      <= inv_res; // k^-1 mod n
                    mult_start <= 1'b1;
                    mult_a     <= r_reg;
                    mult_b     <= d_reg;
                    state      <= ST_SIGN_RD;
                end

                ST_SIGN_RD: if (mult_done) begin
                    add_start <= 1'b1;
                    add_a     <= e_reg;
                    add_b     <= mult_res;
                    state     <= ST_SIGN_ERD;
                end

                ST_SIGN_ERD: if (add_done) begin
                    mult_start <= 1'b1;
                    mult_a     <= k_reg;
                    mult_b     <= add_res;
                    state      <= ST_SIGN_S;
                end

                ST_SIGN_S: if (mult_done) begin
                    res_x     <= r_reg;
                    res_y     <= mult_res;
                    sig_valid <= (r_reg != 256'd0 && mult_res != 256'd0);
                    state     <= ST_DONE;
                end

                // --- ECDSA Verify ---
                ST_VER_W: if (inv_done) begin
                    w_reg      <= inv_res;
                    mult_start <= 1'b1;
                    mult_a     <= e_reg;
                    mult_b     <= inv_res;
                    state      <= ST_VER_U1;
                end

                ST_VER_U1: if (mult_done) begin
                    u1_reg     <= mult_res;
                    mult_start <= 1'b1;
                    mult_a     <= r_reg;
                    mult_b     <= w_reg;
                    state      <= ST_VER_U2;
                end

                ST_VER_U2: if (mult_done) begin
                    u2_reg   <= mult_res;
                    sm_start <= 1'b1;
                    sm_k     <= u1_reg;
                    sm_px    <= BASE_GX;
                    sm_py    <= BASE_GY;
                    state    <= ST_VER_P1;
                end

                ST_VER_P1: if (sm_done) begin
                    p1x      <= sm_qx;
                    p1y      <= sm_qy;
                    sm_start <= 1'b1;
                    sm_k     <= u2_reg;
                    sm_px    <= qx_reg;
                    sm_py    <= qy_reg;
                    state    <= ST_VER_P2;
                end

                ST_VER_P2: if (sm_done) begin
                    p2x <= sm_qx;
                    p2y <= sm_qy;
                    if (u1_reg == 256'd0) begin
                        rx_jac <= reduce_mod_n(sm_qx);
                        res_x  <= reduce_mod_n(sm_qx);
                        res_y  <= sm_qy;
                        sig_valid <= (reduce_mod_n(sm_qx) == r_reg);
                        state  <= ST_DONE;
                    end else if (u2_reg == 256'd0) begin
                        rx_jac <= reduce_mod_n(p1x);
                        res_x  <= reduce_mod_n(p1x);
                        res_y  <= p1y;
                        sig_valid <= (reduce_mod_n(p1x) == r_reg);
                        state  <= ST_DONE;
                    end else begin
                        pad_start <= 1'b1;
                        pad_x1    <= p1x; pad_y1 <= p1y;
                        pad_x2    <= sm_qx; pad_y2 <= sm_qy;
                        state     <= ST_VER_ADD;
                    end
                end

                ST_VER_ADD: if (pad_done) begin
                    if (pad_z3 == 256'd0) begin
                        res_x <= 256'd0; res_y <= 256'd0; sig_valid <= 1'b0;
                        state <= ST_DONE;
                    end else begin
                        rx_jac    <= pad_x3;
                        ry_jac    <= pad_y3;
                        mod_sel   <= CURVE_P;
                        inv_start <= 1'b1;
                        inv_a     <= pad_z3;
                        state     <= ST_VER_ZINV;
                    end
                end

                ST_VER_ZINV: if (inv_done) begin
                    mult_start <= 1'b1;
                    mult_a     <= inv_res;
                    mult_b     <= inv_res;
                    state      <= ST_VER_Z2;
                end

                ST_VER_Z2: if (mult_done) begin
                    mult_start <= 1'b1;
                    mult_a     <= rx_jac;
                    mult_b     <= mult_res;
                    state      <= ST_VER_XR;
                end

                ST_VER_XR: if (mult_done) begin
                    res_x     <= reduce_mod_n(mult_res);
                    res_y     <= ry_jac;
                    sig_valid <= (reduce_mod_n(mult_res) == r_reg);
                    state     <= ST_DONE;
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

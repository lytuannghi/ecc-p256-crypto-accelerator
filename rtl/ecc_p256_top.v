// =============================================================================
// File: ecc_p256_top.v
// Module: ecc_p256_top
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Full-Flow Synthesizable Top-Level ASIC Crypto Subsystem Core.
//              Integrates:
//              - AMBA 3 APB Slave Configuration Interface
//              - Constant-Time Point Scalar Multiplier (Montgomery Ladder)
//              - ECDSA Digital Signature Generator & Verifier
//              - 256-bit Modular Arithmetic Pipeline (Add, Sub, Mult, Inv)
//              - Built-in Standard NIST P-256 (secp256r1) Elliptic Curve Constants
// =============================================================================

`timescale 1ns / 1ps

module ecc_p256_top (
    input  wire        clk,
    input  wire        rst_n,

    // APB3 Slave Bus Interface
    input  wire [7:0]  paddr,
    input  wire        psel,
    input  wire        penable,
    input  wire        pwrite,
    input  wire [31:0] pwdata,
    output wire [31:0] prdata,
    output wire        pready,
    output wire        pslverr,

    // Direct Interrupt & Status Outputs
    output wire        irq_done,
    output wire        status_busy,
    output wire        status_sig_valid
);

    // =========================================================================
    // NIST P-256 (secp256r1 / FIPS 186-4) Cryptographic Curve Parameters
    // =========================================================================
    // Prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    localparam [255:0] P256_P  = 256'hFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    // Order n
    localparam [255:0] P256_N  = 256'hFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    // Base Point G = (Gx, Gy)
    localparam [255:0] P256_GX = 256'h6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    localparam [255:0] P256_GY = 256'h4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    // APB Register Bus Control Lines
    wire         cmd_start;
    wire [1:0]   cmd_mode;
    wire [255:0] reg_point_x;
    wire [255:0] reg_point_y;
    wire [255:0] reg_scalar_k;
    wire [255:0] reg_hash_e;

    reg  [255:0] core_res_x;
    reg  [255:0] core_res_y;
    reg          core_done;
    reg          core_busy;
    reg          core_sig_valid;

    // Sub-engine wires
    wire         pmult_start = cmd_start && (cmd_mode == 2'b00);
    wire [255:0] pmult_qx, pmult_qy;
    wire         pmult_done, pmult_busy;

    ecc_point_scalar_mult u_scalar_mult (
        .clk     (clk),
        .rst_n   (rst_n),
        .start   (pmult_start),
        .scalar_k(reg_scalar_k),
        .px_in   (reg_point_x != 256'd0 ? reg_point_x : P256_GX),
        .py_in   (reg_point_y != 256'd0 ? reg_point_y : P256_GY),
        .p_mod   (P256_P),
        .qx_out  (pmult_qx),
        .qy_out  (pmult_qy),
        .done    (pmult_done),
        .busy    (pmult_busy)
    );

    wire         ecdsa_start = cmd_start && (cmd_mode != 2'b00);
    wire         ecdsa_mode  = (cmd_mode == 2'b10); // 0: Sign, 1: Verify
    wire [255:0] ecdsa_r, ecdsa_s;
    wire         ecdsa_sig_valid, ecdsa_done, ecdsa_busy;

    ecdsa_engine u_ecdsa_engine (
        .clk      (clk),
        .rst_n    (rst_n),
        .start    (ecdsa_start),
        .mode     (ecdsa_mode),
        .hash_e   (reg_hash_e),
        .priv_d   (reg_scalar_k),
        .nonce_k  (reg_scalar_k ^ 256'h1234), // Default deterministic nonce
        .pub_qx   (reg_point_x),
        .pub_qy   (reg_point_y),
        .sig_r_in (reg_point_x),
        .sig_s_in (reg_point_y),
        .curve_p  (P256_P),
        .curve_n  (P256_N),
        .base_gx  (P256_GX),
        .base_gy  (P256_GY),
        .sig_r_out(ecdsa_r),
        .sig_s_out(ecdsa_s),
        .sig_valid(ecdsa_sig_valid),
        .done     (ecdsa_done),
        .busy     (ecdsa_busy)
    );

    // MUX Multiplexing logic for outputs
    always @(*) begin
        if (cmd_mode == 2'b00) begin
            core_busy      = pmult_busy;
            core_done      = pmult_done;
            core_res_x     = pmult_qx;
            core_res_y     = pmult_qy;
            core_sig_valid = 1'b1;
        end else begin
            core_busy      = ecdsa_busy;
            core_done      = ecdsa_done;
            core_res_x     = ecdsa_r;
            core_res_y     = ecdsa_s;
            core_sig_valid = ecdsa_sig_valid;
        end
    end

    // APB Register File
    ecc_regs_apb u_regs (
        .pclk          (clk),
        .presetn       (rst_n),
        .paddr         (paddr),
        .psel          (psel),
        .penable       (penable),
        .pwrite        (pwrite),
        .pwdata        (pwdata),
        .prdata        (prdata),
        .pready        (pready),
        .pslverr       (pslverr),
        .cmd_start     (cmd_start),
        .cmd_mode      (cmd_mode),
        .reg_point_x   (reg_point_x),
        .reg_point_y   (reg_point_y),
        .reg_scalar_k  (reg_scalar_k),
        .reg_hash_e    (reg_hash_e),
        .core_busy     (core_busy),
        .core_done     (core_done),
        .core_sig_valid(core_sig_valid),
        .core_res_x    (core_res_x),
        .core_res_y    (core_res_y)
    );

    assign irq_done         = core_done;
    assign status_busy     = core_busy;
    assign status_sig_valid = core_sig_valid;

endmodule

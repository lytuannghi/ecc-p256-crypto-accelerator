// =============================================================================
// File: ecc_p256_top.v
// Module: ecc_p256_top
// Project: Hardware NIST P-256 ECC Cryptographic Accelerator ASIC
// Description: Full-Flow Synthesizable NIST P-256 Elliptic Curve Cryptography
//              Co-Processor Top-Level with AMBA APB3 Slave Registers and
//              FIPS 186-4 ECDSA Sign / Verify / Scalar Mult Engine.
// =============================================================================

`timescale 1ns / 1ps

module ecc_p256_top (
    input  wire        clk,
    input  wire        rst_n,

    // AMBA 3 APB Slave Bus
    input  wire [7:0]  paddr,
    input  wire        psel,
    input  wire        penable,
    input  wire        pwrite,
    input  wire [31:0] pwdata,
    output wire [31:0] prdata,
    output wire        pready,
    output wire        pslverr,

    // Interrupt & Status Flags
    output wire        irq_done,
    output wire        status_busy,
    output wire        status_sig_valid
);

    wire         cmd_start;
    wire [1:0]   cmd_mode;
    wire [255:0] reg_point_x;
    wire [255:0] reg_point_y;
    wire [255:0] reg_scalar_k;
    wire [255:0] reg_hash_e;
    wire [255:0] reg_sig_r;
    wire [255:0] reg_sig_s;
    wire [255:0] reg_nonce_k;

    wire [255:0] core_res_x;
    wire [255:0] core_res_y;
    wire         core_sig_valid;
    wire         core_done;
    wire         core_busy;

    ecc_regs_apb u_apb_regs (
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
        .reg_sig_r     (reg_sig_r),
        .reg_sig_s     (reg_sig_s),
        .reg_nonce_k   (reg_nonce_k),
        .core_busy     (core_busy),
        .core_done     (core_done),
        .core_sig_valid(core_sig_valid),
        .core_res_x    (core_res_x),
        .core_res_y    (core_res_y)
    );

    ecdsa_engine u_ecdsa (
        .clk       (clk),
        .rst_n     (rst_n),
        .start     (cmd_start),
        .mode      (cmd_mode),
        .pub_qx    (reg_point_x),
        .pub_qy    (reg_point_y),
        .scalar_d  (reg_scalar_k),
        .nonce_k   (reg_nonce_k),
        .sig_r_in  (reg_sig_r),
        .sig_s_in  (reg_sig_s),
        .hash_e    (reg_hash_e),
        .res_x     (core_res_x),
        .res_y     (core_res_y),
        .sig_valid (core_sig_valid),
        .done      (core_done),
        .busy      (core_busy)
    );

    assign irq_done         = core_done;
    assign status_busy      = core_busy;
    assign status_sig_valid = core_sig_valid;

endmodule

# ==============================================================================
# Synthesis Script - Synopsys Design Compiler
# Module: ecc_p256_top
# ==============================================================================

set DESIGN_NAME "ecc_p256_top"
set RTL_DIR "../rtl"
set REPORT_DIR "./reports"
file mkdir $REPORT_DIR

set rtl_files [list \
    "$RTL_DIR/mod_arith/mod_add_sub_256.v" \
    "$RTL_DIR/mod_arith/mod_mult_256.v" \
    "$RTL_DIR/mod_arith/mod_inv_256.v" \
    "$RTL_DIR/point_ops/point_add_double.v" \
    "$RTL_DIR/point_ops/ecc_point_scalar_mult.v" \
    "$RTL_DIR/ecdsa/ecdsa_engine.v" \
    "$RTL_DIR/bus/ecc_regs_apb.v" \
    "$RTL_DIR/ecc_p256_top.v" \
]

foreach file $rtl_files {
    analyze -format verilog $file
}

elaborate $DESIGN_NAME
current_design $DESIGN_NAME

read_sdc ./ecc_timing.sdc
compile_ultra -gate_clock

report_timing -delay_type max -nworst 10 -max_paths 10 > $REPORT_DIR/timing_report.txt
report_area -hierarchy > $REPORT_DIR/area_report.txt
report_power -hierarchy > $REPORT_DIR/power_report.txt
report_qor > $REPORT_DIR/qor_report.txt

write_file -format verilog -hierarchy -output ./netlist/${DESIGN_NAME}_syn.v
write_file -format ddc -hierarchy -output ./netlist/${DESIGN_NAME}_syn.ddc

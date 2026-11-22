# ==============================================================================
# Synopsys Design Constraints (SDC) - NIST P-256 ECC Cryptographic Accelerator ASIC
# Target Technology: TSMC 28nm HPC+ Standard Cell Logic Library
# Operating Corner: Worst-Case Slow-Slow Corner (SSG, 0.90V, 125C)
# Target Frequency: 150.0 MHz (Period = 6.666 ns)
# ==============================================================================

# Master Clock Definition
create_clock -name clk -period 6.666 [get_ports clk]

# Clock Uncertainty & Jitter Modeling
set_clock_uncertainty -setup 0.300 [get_clocks clk]
set_clock_uncertainty -hold  0.100 [get_clocks clk]
set_clock_transition 0.080 [get_clocks clk]

# Input Delays (APB3 Slave Bus)
set_input_delay -clock clk -max 1.500 [get_ports {paddr[*] psel penable pwrite pwdata[*]}]
set_input_delay -clock clk -min 0.300 [get_ports {paddr[*] psel penable pwrite pwdata[*]}]

# Output Delays (APB3 Slave Outputs & Status Flags)
set_output_delay -clock clk -max 1.500 [get_ports {prdata[*] pready pslverr irq_done status_busy status_sig_valid}]
set_output_delay -clock clk -min 0.300 [get_ports {prdata[*] pready pslverr irq_done status_busy status_sig_valid}]

# Drive Strength & Load
set_driving_cell -lib_cell INVX4 [get_ports {paddr[*] psel penable pwrite pwdata[*]}]
set_load 0.030 [all_outputs]

# False Paths
set_false_path -from [get_ports rst_n]

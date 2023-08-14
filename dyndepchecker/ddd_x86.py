import angr
import monkeyhex
import claripy

import ddd_x86_loader
import ddd_x86_runner


p = ddd_x86_loader.load_linux_kernel_project()

ADBSecList, ADESecList = ddd_x86_loader.parse_pc_sections(p)

entry_state = p.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

ADB_state = ddd_x86_runner.execute_concretely(
    p, state=entry_state, address=ddd_x86_runner.get_inst_successor_addr(p, ADBSecList[0][0]))

# Tentative
# ADB_state.regs.rax = rax_sym
# rax_sym = claripy.BVS("rax_sym", 8)
# ADE_state = ddd_x86_runner.execute_concretely(
#     p, state=ADB_state, address=ddd_x86_runner.get_inst_successor_addr(p, ADESecList[0][0]))

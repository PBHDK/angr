import claripy
import ddd_x86_loader
import ddd_x86_runner
import monkeyhex

import angr

p = ddd_x86_loader.load_linux_kernel_project()

ADBToADEDict = ddd_x86_loader.parse_pc_sections(p)

add_options = {
    angr.options.SYMBOLIC_WRITE_ADDRESSES,
    angr.options.TRACK_REGISTER_ACTIONS,
    angr.options.SYMBION_SYNC_CLE,
    angr.options.SYMBION_KEEP_STUBS_ON_SYNC,
}

e_state = p.factory.entry_state(add_options=add_options)

# while not ADBToADEDict:
ADB_state = ddd_x86_runner.execute_concretely(p, state=e_state, addresses=list(ADBToADEDict))

# rax_sym = claripy.BVS("rax_sym", 64)
# ADB_state.regs.rax = rax_sym

# simgr = p.factory.simgr(ADB_state)
# simgr.use_technique(angr.exploration_techniques.DFS())
# simgr.use_technique(angr.exploration_techniques.Explorer(
#     find=ddd_x86_runner.get_inst_successor_addr(p, ADESecList[0][0])))
# simgr.explore()
# ADE_state = simgr.stashes['found'][0]
# simgr.explore(
#     find=ddd_x86_runner.get_inst_successor_addr(p, ADESecList[0][0]))

# Tentative
# ADB_state.regs.rax = rax_sym
# rax_sym = claripy.BVS("rax_sym", 8)
# ADE_state = ddd_x86_runner.execute_concretely(
#     p, state=ADB_state, address=ddd_x86_runner.get_inst_successor_addr(p, ADESecList[0][0]))

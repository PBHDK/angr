import os
import signal
import sys

import claripy
import ddd_x86_loader
import ddd_x86_runner
import monkeyhex
from IPython import embed

import angr


# Drop into ipython when <C-c> is hit
def sigint_handler(signum, frame):
    def kill_script():
        os.system("kill %d" % os.getpid())

    print("Stopping Execution for Debug. If you want to kill the programm issue: kill_script()")
    if "IPython" not in sys.modules:
        import IPython

        IPython.embed()


signal.signal(signal.SIGINT, sigint_handler)

p = ddd_x86_loader.load_linux_kernel_project()

ADBToADEDict = ddd_x86_loader.parse_pc_sections(p)

add_options = {
    angr.options.SYMBOLIC_WRITE_ADDRESSES,
    # angr.options.TRACK_REGISTER_ACTIONS,
    angr.options.SYMBION_SYNC_CLE,
    angr.options.SYMBION_KEEP_STUBS_ON_SYNC,
}

e_state = p.factory.entry_state(add_options=add_options)

while ADBToADEDict:
    ADB_state: angr.SimState = ddd_x86_runner.execute_concretely(p=p, state=e_state, addresses=list(ADBToADEDict))
    ADB_addr: int = ADB_state.addr

    print("Found ADB at {}".format(ADB_addr))
    ADB_regs: list[str] = ddd_x86_runner.get_written_regs(p=p, addr=ADB_addr)

    ADB_succ_state = ddd_x86_runner.execute_concretely(
        p, state=ADB_state, addresses=[ddd_x86_runner.get_inst_successor_addr(p, ADB_addr)]
    )

    ADB_succ_state = ddd_x86_runner.make_regs_symbolic(p=p, s=ADB_succ_state, regs=ADB_regs)
    print(ADB_succ_state.registers.load(ADB_regs[0]).symbolic)

    ddd_x86_runner.execute_symbolically(p=p, s=ADB_succ_state, addr_end=ADBToADEDict[ADB_addr])

    ADBToADEDict.pop(ADB_addr)

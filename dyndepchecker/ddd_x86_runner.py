import capstone
import claripy
import pyvex
from IPython import embed

import angr


def execute_concretely(
    p: angr.Project,
    state: angr.SimState,
    addresses: list[int],
    memory_concretize: list[tuple] = [],
    register_concretize: list[tuple] = [],
    timeout: int = 0,
) -> angr.SimState:
    simgr = p.factory.simgr(state)

    simgr.use_technique(
        angr.exploration_techniques.Symbion(
            find=addresses,
            memory_concretize=memory_concretize,
            register_concretize=register_concretize,
            timeout=timeout,
        )
    )

    exploration = simgr.run()

    return exploration.stashes["found"][0]


def get_inst_successor_addr(p: angr.Project, curr_addr: int) -> int:
    block_addrs = p.factory.block(curr_addr).instruction_addrs
    if len(block_addrs) > 1:
        return block_addrs[1]
    else:
        return -1


# FIXME: this assumes that the first Get is the only register being used.
def get_read_regs(p: angr.Project, addr: int) -> list[str]:
    cap_inst: capstone.CsInsn = p.factory.block(addr).capstone.insns[0]
    regs: list[str] = [cap_inst.reg_name(r) for r in cap_inst.regs_access()[0]]

    if not regs:
        print("Couldn't find registers being read from.")
        embed()

    return regs


# FIXME: this assumes that the first Put is the only register being used.
def get_written_regs(p: angr.Project, addr: int) -> list[str]:
    cap_inst: capstone.CsInsn = p.factory.block(addr).capstone.insns[0]
    regs: list[str] = [cap_inst.reg_name(r) for r in cap_inst.regs_access()[1]]

    if not regs:
        print("Couldn't find registers being written to.")
        embed()

    return regs


# def set_up_sym_write_callbacks(s: angr.SimState, reg: str):
#     s.inspect.b("mem_write", when=angr.BP_BEFORE, action=lambda s: sym_write_val ))


def make_regs_symbolic(p: angr.Project, s: angr.SimState, regs: list[str]) -> angr.SimState:
    for reg in regs:
        reg_val = s.registers.load(reg)
        reg_size = len(reg_val)
        reg_sym = claripy.BVS(reg + "_sym", reg_size)
        s.registers.store(reg, reg_sym)
        s.solver.add(s.registers.load(reg) == reg_val)
    return s


def execute_symbolically(p: angr.Project, s: angr.SimState, addr_end: int) -> angr.SimState:
    end_read_regs = get_read_regs(p, addr_end)

    def debug_func(cs):
        embed()

    s.inspect.b("address_concretization", when=angr.BP_BEFORE, action=debug_func)

    # Assume broken until proven wrong
    # That means we assume the dependency is broken until the exploration finds a
    # symbolic path between the ADB and the ADE.
    def check_broken_dep(s: angr.SimState) -> bool:
        # XXX: This assumes that one of the read registers being symbolic implies a broken dep.
        return s.addr == addr_end and any(s.registers.load(r).symbolic for r in end_read_regs)

    print("Exploring symbolically. Start addr: {}, addr_end {}".format(s.addr, addr_end))

    sm: angr.SimulationManager = p.factory.simgr(s)
    # simgr.use_technique(angr.exploration_techniques.DFS())
    # FIXME: what happens if we encounter a write to a symbolic address on the way?
    # FIXME: is it true that a DFS will leave no ambiguity when resolving symbolilc addresses?
    sm.use_technique(angr.exploration_techniques.DFS())
    sm.explore(find=check_broken_dep)
    if not sm.stashes["found"]:
        print("Broken dependency.")
        embed()
        return s
    else:
        print("Dependency preserved.")
        return sm.stashes["found"][0]

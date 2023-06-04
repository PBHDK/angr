import angr
import avatar2 as avatar2
from angr_targets import R2ConcreteTarget

# Enable debug output
import logging
logging.getLogger('GDBProtocol').setLevel('DEBUG')

ADBPCSTR = "AddrDepBeginnings"
ADEPCSTR = "AddrDepEndings"
VMLINUX_PATH = "/scratch/paul/src/linux/vmlinux"

GDB_EXECUTABLE = "aarch64-unknown-linux-gnu-gdb"
GDB_SERVER_IP = "127.0.0.1"
GDB_SERVER_PORT = 1234


def find_broken_dependencies(self, p, state, PCADB, PCADE, ID):
    new_concrete_state = self.execute_concretly(p, state, PCADB, [])
    # the_sp = new_concrete_state.solver.eval(new_concrete_state.regs.sp)


def execute_concretely(p, state, address, memory_concretize=[],
                       register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)
    simgr.use_technique(
        angr.exploration_techniques.Symbion(
            find=[address], memory_concretize=memory_concretize,
            register_concretize=register_concretize,
            timeout=timeout))

    exploration = simgr.run()

    return exploration.stashes['found'][0]


def main():
    # TODO: start syzkaller from here
    # Instantiation of the AvatarGDBConcreteTarget
    # avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
    #                                      gdbserver_ip=GDB_SERVER_IP,
    #                                      gdbserver_port=GDB_SERVER_PORT,
    #                                      gdb_executable=GDB_EXECUTABLE)

    r2Target = R2ConcreteTarget()

    p = angr.Project(VMLINUX_PATH,
                     concrete_target=r2Target,
                     use_sim_procedures=True, arch="arm64")

    mobj = p.loader.main_object

    SecADBs = next(filter(lambda sec: sec.name == ADBPCSTR, mobj.sections))
    SecADEs = next(filter(lambda sec: sec.name == ADEPCSTR, mobj.sections))

    PCsADBsRaw = bytes.hex(p.loader.memory.load(
        SecADBs.vaddr, SecADBs.memsize))
    PCsADEsRaw = bytes.hex(p.loader.memory.load(
        SecADEs.vaddr, SecADEs.memsize))

    # Contain (PC addr in hex, ID str) pairs
    PCsADBsList = [(int(PCsADBsRaw[i:i+8], 16), str(PCsADBsRaw[i+8:i+24]))
                   for i in range(0, len(PCsADBsRaw), 24)]
    PCsADEsList = [(int(PCsADEsRaw[i:i+8], 16), str(PCsADEsRaw[i+8:i+24]))
                   for i in range(0, len(PCsADEsRaw), 24)]

    entry_state = p.factory.entry_state()
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

    print(execute_concretely(p, entry_state, PCsADBsList[0][0]))


if __name__ == "__main__":
    main()

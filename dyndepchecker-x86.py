import angr
import avatar2 as avatar2
# from angr_targets import AvatarGDBConcreteTarget
from angr_targets import AvatarGDBConcreteTarget

# Enable debug output
import logging
logging.getLogger('GDBProtocol').setLevel('DEBUG')

ADBPCSTR = "AddrDepBeginnings"
ADEPCSTR = "AddrDepEndings"
VML_PATH = "/scratch/paul/src/linux/vmlinux"

# Size of a PC section entry in bits
PC_ENT_SIZE = 96

# GDB_EXECUTABLE = "aarch64-unknown-linux-gnu-gdb"
GDB_EXECUTABLE = "gdb"
GDB_SERVER_IP = "127.0.0.1"
GDB_SERVER_PORT = 1234


def find_broken_dependencies(self, p, state, PCADB, PCADE, ID):
    new_concrete_state = self.execute_concretly(p, state, PCADB, [])
    # the_sp = new_concrete_state.solver.eval(new_concrete_state.regs.sp)


def execute_concretely(p, state, address, memory_concretize=[],
                       register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)

    print(address)

    simgr.use_technique(
        angr.exploration_techniques.Symbion(
            find=[address], memory_concretize=memory_concretize,
            register_concretize=register_concretize,
            timeout=timeout))

    # exploration = simgr.run()

    # return exploration.stashes['found'][0]
    return None


def main():
    # TODO: start syzkaller from here
    # Instantiation of the AvatarGDBConcreteTarget
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                         gdbserver_ip=GDB_SERVER_IP,
                                         gdbserver_port=GDB_SERVER_PORT,
                                         gdb_executable=GDB_EXECUTABLE)

    p = angr.Project(VML_PATH,
                     concrete_target=avatar_gdb,
                     use_sim_procedures=True, arch="x86_64")

    mobj = p.loader.main_object

    ADBSec = next(filter(lambda sec: sec.name == ADBPCSTR, mobj.sections))
    ADESec = next(filter(lambda sec: sec.name == ADEPCSTR, mobj.sections))

    ADBBase = ADBSec.vaddr
    ADEBase = ADESec.vaddr

    ADBSecRaw = bytes.hex(p.loader.memory.load(ADBSec.vaddr, ADBSec.memsize))
    ADESecRaw = bytes.hex(p.loader.memory.load(ADESec.vaddr, ADESec.memsize))

    # Contain (PC addr in hex, ID str) pairs
    ADBSecList = [(int(ADBSecRaw[i:i+8], 16) + ADBBase + i * PC_ENT_SIZE,
                   str(ADBSecRaw[i+8:i+24]))
                  for i in range(0, len(ADBSecRaw), 24)]

    ADESecList = [(int(ADESecRaw[i:i+8], 16) + ADEBase + i * PC_ENT_SIZE,
                   str(ADESecRaw[i+8:i+24]))
                  for i in range(0, len(ADESecRaw), 24)]

    entry_state = p.factory.entry_state()
    entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
    entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

    print(execute_concretely(p, entry_state, ADBSecList[0][0]))


if __name__ == "__main__":
    main()

import angr
import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
from cle import backends

VML_PATH = "/scratch/paul/src/linux/vmlinux"
GDB_EXECUTABLE = "gdb"
GDB_SERVER_IP = "127.0.0.1"
GDB_SERVER_PORT = 1234

ADBPCSTR = "AddrDepBeginnings"
ADEPCSTR = "AddrDepEndings"

# Size of a PC section entry in bits
PC_ENT_SIZE = 96

# Enable debug output
# import logging
# logging.getLogger('GDBProtocol').setLevel('DEBUG')


def parse_pc_sections(p: angr.Project):
    mobj = p.loader.main_object

    ADBSec: backends.Region = next(
        filter(lambda sec: sec.name == ADBPCSTR, mobj.sections))
    ADESec = next(filter(lambda sec: sec.name == ADEPCSTR, mobj.sections))

    ADBBaseAddr = ADBSec.vaddr
    ADEBaseAddr = ADESec.vaddr

    ADBSecRaw: bytes = p.loader.memory.load(ADBBaseAddr, ADBSec.memsize)
    ADESecRaw: bytes = p.loader.memory.load(ADEBaseAddr, ADESec.memsize)

    # Contain (PC addr, ID str) pairs
    # The PC address is computed as: first 4 bytes at address of entry i + offset
    # The address of entry i is computed as: section address + i * section size
    #
    # The ID is composed of 8 little-endian bytes. The ID is signed.
    ADBSecList = [(int.from_bytes(ADBSecRaw[i:i+4], "little", True) + ADBBaseAddr + i * PC_ENT_SIZE,
                   int.from_bytes(ADBSecRaw[i+4:i+12], "little", True))
                  for i in range(0, len(ADBSecRaw), 12)]

    ADESecList = [(int.from_bytes(ADESecRaw[i:i+4], "little", True) + ADEBaseAddr + i * PC_ENT_SIZE,
                   int.from_bytes(ADESecRaw[i+4:i+12], "little", True))
                  for i in range(0, len(ADESecRaw), 12)]

    return ADBSecList, ADESecList


def load_linux_kernel_project():
    # TODO: start syzkaller from here
    # Instantiation of the AvatarGDBConcreteTarget
    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                         gdbserver_ip=GDB_SERVER_IP,
                                         gdbserver_port=GDB_SERVER_PORT,
                                         gdb_executable=GDB_EXECUTABLE)

    p = angr.Project(VML_PATH,
                     concrete_target=avatar_gdb,
                     use_sim_procedures=True, arch="x86_64")

    return p

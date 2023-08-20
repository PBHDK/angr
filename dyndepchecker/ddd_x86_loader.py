import avatar2 as avatar2
from angr_targets import AvatarGDBConcreteTarget
from cle import backends

import angr

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


def get_inst_successor_addr(p: angr.Project, curr_addr: int) -> int:
    block_addrs = p.factory.block(curr_addr).instruction_addrs
    if len(block_addrs) > 1:
        return block_addrs[1]
    else:
        return -1


def parse_pc_sections(p: angr.Project) -> dict[int, int]:
    def convert_offset_to_pc(raw_section: bytes, base_addr: int, ind: int) -> int:
        return base_addr + ind * PC_ENT_SIZE + int.from_bytes(raw_section[ind : ind + 4], "little", True)

    def get_pc_sec_entry_id(raw_section: bytes, ind: int) -> int:
        return int.from_bytes(raw_section[ind + 4 : ind + 12], "little", True)

    mobj = p.loader.main_object

    ADBSec: backends.Region = next(filter(lambda sec: sec.name == ADBPCSTR, mobj.sections))
    ADESec: backends.Region = next(filter(lambda sec: sec.name == ADEPCSTR, mobj.sections))

    ADBBaseAddr = ADBSec.vaddr
    ADEBaseAddr = ADESec.vaddr

    ADBSecRaw: bytes = p.loader.memory.load(ADBBaseAddr, ADBSec.memsize)
    ADESecRaw: bytes = p.loader.memory.load(ADEBaseAddr, ADESec.memsize)

    # Contain (PC addr, ID str) pairs
    # The PC address is computed as: first 4 bytes at address of entry i + offset
    # The address of entry i is computed as: section address + i * section size asdf asdf awef
    #
    # The ID is composed of 8 little-endian bytes. The ID is signed.
    ADB_ID_Dict: dict[int, int] = {
        get_pc_sec_entry_id(ADBSecRaw, i): convert_offset_to_pc(ADBSecRaw, ADBBaseAddr, i)
        for i in range(0, len(ADBSecRaw), 12)
    }

    ADE_ID_Dict: dict[int, int] = {
        get_pc_sec_entry_id(ADESecRaw, i): convert_offset_to_pc(ADESecRaw, ADEBaseAddr, i)
        for i in range(0, len(ADESecRaw), 12)
    }

    ADBToADEDict = {ADB_ID_Dict[ID]: ADE_ID_Dict[ID] for ID, _ in ADB_ID_Dict.items()}

    ADBSuccToADESuccDict: dict[int, int] = {
        get_inst_successor_addr(p, beg): get_inst_successor_addr(p, end) for beg, end in ADBToADEDict.items()
    }

    # At this point we don't need the IDs anymore.
    # We have matched the final PCs of the ADBs and ADEs respectively.
    return ADBSuccToADESuccDict


def load_linux_kernel_project() -> angr.Project:
    # TODO: start syzkaller from here
    # Instantiation of the AvatarGDBConcreteTarget
    avatar_gdb = AvatarGDBConcreteTarget(
        architecture=avatar2.archs.x86.X86_64,
        gdbserver_ip=GDB_SERVER_IP,
        gdbserver_port=GDB_SERVER_PORT,
        gdb_executable=GDB_EXECUTABLE,
    )

    p = angr.Project(VML_PATH, concrete_target=avatar_gdb, use_sim_procedures=True, arch="x86_64")

    return p

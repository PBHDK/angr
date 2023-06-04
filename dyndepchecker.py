import angr

ADBPCStr = "AddrDepBeginnings"
ADEPCStr = "AddrDepEndings"
LinuxBinaryPath = "/scratch/paul/src/linux/vmlinux"

proj = angr.Project(LinuxBinaryPath, load_options={"auto_load_libs": "false"})

mobj = proj.loader.main_object

SecADBs = next(filter(lambda sec: sec.name == ADBPCStr, mobj.sections))
SecADEs = next(filter(lambda sec: sec.name == ADEPCStr, mobj.sections))

PCsADBsBin = int(proj.loader.memory.load(SecADBs.vaddr, SecADBs.memsize), 2)
PCsADEsBin = int(proj.loader.memory.load(SecADEs.vaddr, SecADEs.memsize), 2)

# Contain (PC addr in hex, ID str) pairs
PCsADBs = [(hex(PCsADBsBin[i:i+32]), str(int(PCsADBsBin[i+32:i+96])))
           for i in range(len(PCsADBsBin) % 96)]
PCsADEs = [(hex(PCsADEsBin[i:i+32]), str(int(PCsADEsBin[i+32:i+96])))
           for i in range(len(PCsADEsBin) % 96)]

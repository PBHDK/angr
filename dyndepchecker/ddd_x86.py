import angr

import ddd_x86_loader
import ddd_x86_runner


p = ddd_x86_loader.load_linux_kernel_project()

ADBSecList, ADESecList = ddd_x86_loader.parse_pc_sections(p)

entry_state = p.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

# print(ddd_x86_runner.execute_concretely(p, entry_state, ADBSecList[0][0]))

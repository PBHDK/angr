import angr
# from angr_targets import AvatarGDBConcreteTarget


def find_broken_dependencies(self, p, state, PCADB, PCADE, ID):
    # new_concrete_state = self.execute_concretly(p, state, PCADB, [])
    # the_sp = new_concrete_state.solver.eval(new_concrete_state.regs.sp)
    pass


def execute_concretely(p: angr.Project, state, address, memory_concretize=[],
                       register_concretize=[], timeout=0):
    simgr = p.factory.simgr(state)

    simgr.use_technique(
        angr.exploration_techniques.Symbion(
            find=[address], memory_concretize=memory_concretize,
            register_concretize=register_concretize,
            timeout=timeout))

    exploration = simgr.run()

    return exploration.stashes['found'][0]

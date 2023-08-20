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


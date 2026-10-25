# Scope — iPhone15,3 / iOS 16.2 runtime failure audit

- Date: 2026-09-17
- Authorization: owner-requested, read-only audit of the Opamine `rhinject` workspace and supplied device log
- In scope:
  - branch `rhinject` at `1cabcbf0df1a552e3794a75f4b125ebe0a20a1dc`
  - the published `Dopamine2-rhinject.tipa` with SHA-256 `82aaf9b6d3ee3439f7e5df7de200fa30abd0bfecc554459dfbb3493099d44753`
  - the user-supplied iPhone15,3 / iOS 16.2 log
  - RootHide bootstrap rerandomization, BaseBin trust, systemhook loading, finalization, and failure recovery
- Out of scope:
  - live device mutation or dynamic instrumentation
  - implementation changes
  - deleting or repairing randomized jailbreak roots
  - publication or release changes
- Network profile: read-only Git/GitHub reference checks only
- Completion limit: the immediate abort and reboot-only recovery may be established statically; the exact dyld rejection remains a candidate until a device captures `dlerror()` and active root/dependency state.


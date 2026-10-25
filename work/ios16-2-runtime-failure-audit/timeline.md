# Timeline — iPhone15,3 / iOS 16.2 failure

- 2026-09-17 14:57:31 — Dopamine starts on iPhone15,3, iOS 16.2 (20C65), with tweaks enabled and app JIT disabled.
- Exploit through PPL bypass, physical read/write construction, exploit cleanup, privilege elevation, and randomized-root discovery succeed.
- Existing jailbreak root is rerandomized and BaseBin is replaced.
- BaseBin trust-cache loading, launchd injection, and RootHide Stage complete successfully according to the application log.
- A first `roothider_main.c:1468` assertion appears during the ignored `killall iconservicesagent` helper launch.
- `Updating Symlinks` starts.
- A second line-1468 assertion aborts the shell used to run `updatelinks.sh`.
- Bootstrap finalization reports raw child wait status `6`; the application presents the failure log.
- Launchd remains in first-load state and deliberately returns `EPERM` for a later Dopamine spawn. A full reboot clears that state.


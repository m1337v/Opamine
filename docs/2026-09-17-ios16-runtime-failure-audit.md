# iPhone15,3 / iOS 16.2 RootHide runtime failure audit

- Date: 2026-09-17
- Target: Opamine `rhinject` at `1cabcbf0df1a552e3794a75f4b125ebe0a20a1dc`
- Device evidence: iPhone15,3, iOS 16.2 (20C65)
- Status: root call path and reboot-only recovery validated; exact dyld rejection pending one instrumented device run
- Scope: [`work/ios16-2-runtime-failure-audit/scope.md`](../work/ios16-2-runtime-failure-audit/scope.md)
- Timeline: [`work/ios16-2-runtime-failure-audit/timeline.md`](../work/ios16-2-runtime-failure-audit/timeline.md)

## Executive summary

The kernel exploit is not the failing subsystem. The supplied log reaches successful PPL bypass, physical read/write construction, exploit cleanup, privilege elevation, BaseBin trust-cache upload, launchd injection, and RootHide Stage completion.

The first fatal condition is `systemhook` calling `dlopen()` for the installed `basebin/roothidehooks.dylib` and aborting because the returned handle is `NULL`. This happens once in the ignored `killall iconservicesagent` helper and again in the shell that should run `updatelinks.sh`. The reported value `6` is the raw wait status for the assertion's `SIGABRT`, not an application-defined `updatelinks` error.

The leading cause is a broken loader contract immediately after jailbreak-root rerandomization: `roothidehooks.dylib` and RootHide Core use nested `@loader_path/.jbroot/...` dependencies, while rerandomization repairs only the paired-root links and relies on later/implicit machinery for nested links. A post-randomization trust/CDHash rejection remains the other serious candidate. The code discards the only decisive evidence by asserting without recording `dlerror()`.

The inability to reopen Dopamine is intentional but poorly surfaced. Once launchd is injected in first-load mode, it explicitly returns `EPERM` for subsequent Dopamine launches until a userspace/full reboot completes initialization. The late error path performs no meaningful cleanup on iOS 16.2 and does not force or clearly offer a reboot, leaving the device in a half-activated state.

## Scope and constraints

This was a read-only source, package, artifact, and log audit. No live device was attached, so the report distinguishes validated behavior from candidate root causes. The published TIPA was inspected independently of stale local ignored build products.

## Evidence

### E-001 — Supplied device log

- source_ref: `/Users/a1337/.codex/attachments/1c32dd29-f3cc-478d-9ee5-e3b7d3a83776/pasted-text.txt`
- source_type: log
- content_hash: `b5b9c100de465546449e1641246450504c46a4e1e5c1150cdbcc24ef128ad20e`
- repro_command: `shasum -a 256 <log>; nl -ba <log> | sed -n '1,289p'`
- observation: lines 165–193 show exploit/PPL/launchd/RootHide success; lines 283–288 show the line-1468 assertions and final raw status 6.

### E-002 — Abort and helper call path

- source_ref: `BaseBin/systemhook/src/roothider_main.c`, `BaseBin/systemhook/src/roothider.h`, `Application/Dopamine/Jailbreak/DOBootstrapper.m`, `BaseBin/libjailbreak/src/util.c`
- source_type: source
- content_hash: Git blobs `9b2e3a3f9a74d7aaacd9c2c45a0417f511f7e5ab` (`roothider_main.c`) and `ed6b4ba178c060e3fadd2d42266d27fccf4378b4` (`DOBootstrapper.m`)
- repro_command: `nl -ba BaseBin/systemhook/src/roothider_main.c | sed -n '1460,1474p'; nl -ba BaseBin/systemhook/src/roothider.h | sed -n '8,24p'; nl -ba Application/Dopamine/Jailbreak/DOBootstrapper.m | sed -n '1710,1730p'; nl -ba BaseBin/libjailbreak/src/util.c | sed -n '850,910p'`
- observation: line 1468 is reached only when `dlopen(...roothidehooks.dylib, RTLD_NOW)` returns `NULL`; `ASSERT` calls `abort_with_reason` and then `abort`; `exec_cmd` returns raw `waitpid` status.

### E-003 — Published artifact and Mach-O dependency contract

- source_ref: published `Dopamine2-rhinject.tipa`
- source_type: binary artifact
- content_hash: TIPA `82aaf9b6d3ee3439f7e5df7de200fa30abd0bfecc554459dfbb3493099d44753`; embedded `roothidehooks.dylib` `60aa6399556e8f0c00589b92e9c129c699248f10adc6330a399b28cc0b345f73`
- repro_command: extract `Payload/Dopamine.app/basebin.tar`, then run `file`, `xcrun vtool -show-build`, `otool -arch arm64e -L`, and `nm -u` on `basebin/roothidehooks.dylib`
- observation: the hook contains arm64 and arm64e slices, minimum iOS 15.0, the final `dlsym` XPC workaround, and hard dependencies on sibling `libjailbreak.dylib`, `@loader_path/.jbroot/usr/lib/libroothide.dylib`, and a present/fallback CydiaSubstrate rpath.

### E-004 — RootHide Core loader links

- source_ref: `Application/Dopamine/Resources/roothide.deb` version `0.1.0-0+opamine1`
- source_type: package/binary
- content_hash: package `6c2c521d33a668829e719f489676817b74d0c19e5f79065f6c9cf81b623810c1`; `libroothide.dylib` `2bc19019163439797d623309ca380f82b29879faf0757f102417683a9b000e48`
- repro_command: `dpkg-deb -x Application/Dopamine/Resources/roothide.deb <dir>; otool -L <dir>/usr/lib/libroothide.dylib; strings <dir>/usr/libexec/updatelink`
- observation: `libroothide.dylib` itself depends on `@loader_path/.jbroot/usr/lib/roothideinit.dylib`; `updatelink` also depends on RootHide-relative loading. Nested `.jbroot` links are therefore bootstrapping dependencies, not cosmetic links.

### E-005 — Rerandomization and recovery state

- source_ref: `Application/Dopamine/Jailbreak/DOBootstrapper.m`, `Application/Dopamine/Jailbreak/DOJailbreaker.m`, `BaseBin/launchdhook/src/roothider.m`
- source_type: source
- content_hash: Git blobs `ed6b4ba178c060e3fadd2d42266d27fccf4378b4` and `158e1822ac538cf7d0fb6a554d9b5a2eb73c8b4`
- repro_command: inspect `ReRandomizeBootstrap`, `cleanUpPostExploitation`, and the `launchdhookFirstLoad` Dopamine gate
- observation: rerandomization commits before finalization; post-exploitation cleanup is effective only on iOS 17+; launchd deliberately denies a later Dopamine spawn while first-load activation is incomplete.

### E-006 — Host verification

- source_ref: `Scripts/verify_dopamine3_baseline.sh`
- source_type: command
- content_hash: n/a
- repro_command: `bash Scripts/verify_dopamine3_baseline.sh`
- observation: the full host baseline passed, including 49 systemhook characterization cases and trust-cache model tests. Those tests do not exercise an iOS 16 dyld load after root rerandomization or a post-launchd failure recovery.

## Findings

### F-001 — `roothidehooks.dylib` load failure aborts every privileged bootstrap child

- severity: high
- category: reliability/design
- status: validated
- evidence_ids: E-001, E-002, E-003
- confidence: high
- location: `BaseBin/systemhook/src/roothider_main.c:1463`
- impact: finalization cannot run; ignored helpers also abort; the device remains partially activated.
- remediation: record the loader error and active root/dependency state, then propagate a controlled bootstrap error. A hard assertion without diagnostics is not an acceptable boundary for an expected runtime load failure.

The first assertion precedes `Updating Symlinks` and is consistent with the ignored `killall iconservicesagent` call. The second aborts `/bin/sh`. Fixing only `updatelinks.sh` would miss the shared loader failure.

### F-002 — Nested `.jbroot` state is the leading primary cause

- severity: high
- category: design
- status: candidate
- evidence_ids: E-003, E-004, E-005
- confidence: medium
- location: `DOBootstrapper.m:1386`, `roothider_main.c:1467`
- impact: dyld cannot resolve RootHide Core or `roothideinit` after the randomized root moves, so every process that calls `loadPathHook()` aborts.
- remediation: make nested `.jbroot` repair an explicit, validated part of the rerandomization transaction and recreate the BaseBin-local link immediately after BaseBin extraction.

The transaction repairs `newPrimary/private/var` and `newSecondary/.jbroot`, but it does not transactionally repair nested `.jbroot` links under the moved primary/secondary trees. The newly extracted BaseBin archive contains no `basebin/.jbroot`. Current success depends on implicit dependency-trust traversal creating/repairing these links before the first load. That ordering is fragile and creates a bootstrap cycle: `updatelinks.sh` is supposed to repair links, but its shell needs the links to load `roothidehooks` first.

This finding becomes validated when `dlerror()` reports the missing `.jbroot`/RootHide dependency or an on-device link inventory shows the stale target at the failure point.

### F-003 — BaseBin trust-cache success can hide a required-file failure

- severity: medium
- category: design
- status: validated as an observability/error-propagation defect; causal role candidate
- evidence_ids: E-003, E-006
- confidence: high for the defect, medium-low for causality
- location: `BaseBin/libjailbreak/src/roothider/common.m:983`
- impact: the UI can log successful BaseBin trust-cache loading even if a particular Mach-O, including `roothidehooks`, failed CDHash randomization. The aggregate operation succeeds as long as at least one file produced a hash.
- remediation: propagate enumeration and per-required-file failures; collect every applicable architecture slice; after upload, verify the device-selected randomized CDHash for `roothidehooks`, `systemhook`, and `libjailbreak` is trusted.

The packaged static trust cache includes the hook and is internally consistent, but RootHide removes that static file and builds a randomized runtime trust cache. Static archive inspection therefore does not prove the active arm64e hash was uploaded.

### F-004 — Reboot-only recovery is an explicit launchd gate, not a UI mystery

- severity: high
- category: lifecycle/recovery
- status: validated
- evidence_ids: E-001, E-005
- confidence: high
- location: `BaseBin/launchdhook/src/roothider.m:811`
- impact: after any late first-load failure, a fresh Dopamine launch returns `EPERM` until reboot. The current failure UI does not explain this state or guarantee a safe reboot path.
- remediation: treat any post-launchd/pre-userspace-reboot error as reboot-required. Preserve/share logs, then invoke a direct privileged full-reboot mechanism that does not depend on another BaseBin helper. Do not attempt a normal app relaunch in this state.

The launchd hook comment explicitly says it prevents Dopamine relaunch after interrupted activation to avoid operating in an unknown state. `cleanUpPostExploitation` cannot undo this and is a no-op on iOS 16.2. Trust caches, launchd/jailbreakd state, rerandomized roots, and replaced BaseBin also remain committed.

### F-005 — Xcode 15 is not the observed runtime cause

- severity: info
- category: compatibility
- status: validated
- evidence_ids: E-001, E-003
- confidence: high
- location: published artifact metadata
- impact: changing toolchains without addressing loader/root state is unlikely to fix the device failure.
- remediation: keep the established Xcode 15.4 CI compatibility work; diagnose the runtime loader result first.

The published hook supports iOS 15.0+, has both required slices, and contains the final runtime `dlsym` workaround. The log also proves that other BaseBin components and launchd injection execute on iOS 16.2.

## Call path

### P-001 — Successful exploit to unrecoverable first-load state

- path_type: callflow
- start: user starts jailbreak on iPhone15,3 / iOS 16.2
- goal: explain the bootstrap abort and reboot-only recovery
- steps:
  1. exploit, PPL bypass, physical R/W, and exploit cleanup succeed — evidence: E-001 — finding: none
  2. existing primary/secondary roots are rerandomized and BaseBin is replaced — evidence: E-001, E-005 — finding: F-002
  3. randomized BaseBin trust cache reports success — evidence: E-001, E-006 — finding: F-003
  4. launchd is injected in first-load mode; RootHide Stage completes — evidence: E-001, E-005 — finding: F-004
  5. helper process loads `systemhook`; `redirect_paths()` calls `loadPathHook()` — evidence: E-002 — finding: F-001
  6. `dlopen(roothidehooks, RTLD_NOW)` returns `NULL`; absent `dlerror()` prevents exact classification — evidence: E-001, E-002 — finding: F-001, F-002
  7. assertion produces `SIGABRT`; raw wait status 6 is reported as the script result — evidence: E-001, E-002 — finding: F-001
  8. the error path returns without userspace reboot; launchd later rejects Dopamine with `EPERM` — evidence: E-005 — finding: F-004
- residual_risks: repeated attempts before reboot operate against a partially updated randomized root and boot-global state.

## Implementation handoff

The work should be split into small commits in this order. Luna Max can implement the bounded source/test work from these instructions; Sol should review the root transaction and release decision.

### WP1 — Capture the decisive loader evidence

Owner: Luna Max. Risk: low. No behavior change beyond diagnostics.

1. Replace both direct `roothidehooks` loads in `roothider_main.c` with one internal helper.
2. Call `dlerror()` once before `dlopen()` to clear stale state, call `dlopen`, preserve `errno`, and capture `dlerror()` immediately on failure.
3. Log the requested path, `JB_RootPath`, `get_jbroot()`, executable path, architecture, PID/PPID/EUID, and the saved dyld error.
4. On failure, `lstat`, `readlink`, and `realpath` only these bounded paths:
   - active root
   - `basebin/roothidehooks.dylib`
   - `basebin/libjailbreak.dylib`
   - `basebin/.jbroot`
   - `usr/lib/.jbroot`
   - `usr/lib/libroothide.dylib`
   - `usr/lib/roothideinit.dylib`
   - `basebin/present` and `basebin/fallback/CydiaSubstrate.framework/CydiaSubstrate`
5. Keep the current fail-closed behavior for the first diagnostic build, but include the actual error in the abort reason.
6. Add a source-contract test proving `dlerror()` is captured before any second loader operation can consume it.

Exit gate: the next device log contains one unambiguous dyld error plus resolved root/link state.

### WP2 — Make critical `.jbroot` repair transactional

Owner: Luna Max with Sol review. Risk: medium-high.

1. In `ReRandomizeBootstrap`, inventory nested symlinks named exactly `.jbroot` under the owned primary and secondary roots without following symlinks.
2. Accept only links whose destination is the validated old primary root. Treat any other destination or non-symlink node as an error; never overwrite it.
3. After moving both roots, replace each accepted link atomically with a link to the validated new primary root. Record every replacement for rollback.
4. Include these replacements in the existing reverse-order rollback before moving the roots back.
5. After BaseBin extraction, explicitly create or validate `<activeRoot>/basebin/.jbroot -> <activeRoot>` before trust-cache generation. Do not rely on `updatelinks.sh` or trust traversal to create it.
6. Explicitly validate `usr/lib/.jbroot` and `usr/libexec/.jbroot`, because RootHide Core and `updatelink` use those loader-relative paths.
7. Keep `/var/jb` as a compatibility link only; all validation must use the owned randomized primary root.

Exit gate: first bootstrap, one rerandomization, rollback injection at every operation, and a second rerandomization all leave exactly one valid root pair and every critical `.jbroot` resolving to the active primary.

### WP3 — Make BaseBin trust generation fail closed per required image

Owner: Luna Max with Sol review. Risk: medium.

1. Refactor `randomizeAndLoadBasebinTrustcache` to use status-returning Mach-O collection instead of ignoring `ensure_randomized_cdhash` failures.
2. Distinguish non-Mach files (intentional skip) from malformed/unreadable Mach-O files (error).
3. Collect and deduplicate all mappable slices using the existing `file_collect_untrusted_cdhashes_by_path_status` rules.
4. Require successful collection for `roothidehooks.dylib`, `systemhook.dylib`, `libjailbreak.dylib`, launchdhook, and the device-selected dyldhook image.
5. After uploading `BASEBIN_TRUSTCACHE_UUID`, verify each required device-selected randomized CDHash with `is_cdhash_trustcached`.
6. Add arm64, old-arm64e dylib, arm64e ABI-v2, malformed FAT, non-Mach, partial-directory-error, and duplicate-CDHash fixtures.

Exit gate: the UI cannot report trust-cache success if any required runtime image is absent, malformed, unrandomized, or untrusted.

### WP4 — Contain late first-load failures

Owner: Terra or Sol. Risk: high because launchd is already modified.

1. Introduce an explicit activation phase enum: pre-injection, launchd-first-load, finalized, userspace-rebooting.
2. For failures before launchd injection, restore process-local environment and credentials where the OS-specific restoration is proven safe.
3. For failures after launchd injection and before userspace reboot, do not claim rollback. Mark the error reboot-required and preserve the primary error/log.
4. Present Share Log and Reboot actions. Reboot must use a direct privileged path from the already elevated app, not `exec_cmd_trusted` through a BaseBin helper that may hit the same loader failure.
5. Prevent dismissal into the current `suspend`/`exit` path until the user explicitly chooses reboot or acknowledges that Dopamine cannot relaunch.
6. Decode child status with `WIFEXITED/WEXITSTATUS/WIFSIGNALED/WTERMSIG` in the displayed error.

Exit gate: a forced late failure produces a useful log, clearly requires reboot, and never suggests retrying the app in the same boot.

### WP5 — Device matrix and release gate

Owner: device operator plus Sol release review.

| Scenario | Required result |
| --- | --- |
| iPhone15,3 / 16.2 existing bootstrap | one successful rerandomization and userspace reboot |
| same device, second activation | idempotent finalization; no link changes or abort |
| first bootstrap | critical links exist before first BaseBin helper |
| missing `basebin/.jbroot` fault | bounded diagnostic or preflight failure; no silent abort |
| invalid required CDHash fault | trust-cache stage fails before launchd injection |
| forced failure after launchd injection | explicit reboot-required UI; reboot succeeds without helper spawn |
| app JIT on/off | identical bootstrap-internal hook loading |
| arm64e iOS 15.x | no regression in old ABI selection or spinlock path |
| arm64 iOS 16.x | no regression in fallback slice or path repair |
| clean install / upgrade / remove | one owned root pair; package pins and hidden-injection policy preserved |

Do not publish a fixed artifact until the embedded BaseBin hash, TIPA hash, branch commit, release tag, and on-device installed hashes are recorded together.

## Independent advisor review

An Astra medium advisor reviewed the initial analysis. It agreed that the line-1468 loader abort is primary, reboot-only behavior is a separate lifecycle defect, nested `.jbroot` state is the leading hypothesis, and no exact primary cause should be claimed without `dlerror()` and active-root evidence. It also recommended decoding raw child status, testing same-PID versus fresh-PID behavior, and treating post-launchd failures as reboot-required rather than pretending they are reversible.

## Immediate operator guidance

After this failure, perform a full reboot before another attempt. Do not repeatedly tap Dopamine, manually delete randomized roots, or glob-remove `.jbroot-*` directories. After reboot, use an instrumented build for the next run; the current log does not contain enough dyld detail to choose safely between link/dependency and trust/CDHash fixes.

## Residual uncertainty

- The device's installed TIPA/BaseBin hash was not captured. If it was the published `82aaf9...` artifact, the final XPC `dlsym` fix is present; otherwise artifact identity must be established first.
- No device `dlerror()`, dyld crash reason, active trust-cache dump, or nested-link inventory was supplied.
- Host tests validate source contracts and models, not the iOS 16 arm64e loader seam or the first-load launchd recovery state.


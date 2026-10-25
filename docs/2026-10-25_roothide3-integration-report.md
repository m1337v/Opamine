# Integrating RootHide 3 into Opamine

This integration brings upstream RootHide support for Dopamine 3.0.12 into the modified `rhinject` branch. Upstream moves RootHide services into `libroothider`, changes the launchd/check-in ABI, introduces the newer hookd path, and supplies six OS/architecture-specific dyldhook images. The fork retains its custom injection modes, selected-tweak/hider subsystem, owned-root recovery, strict trust-cache updates, loader diagnostics, and fork package protections.

Scope and authorization are recorded in [the integration scope](../work/roothide3-merge-2026-10-25/scope.md). A successful host build does not establish that the previously failing iPhone15,3/iOS 16.2 startup seam works on-device. That runtime check remains a release acceptance requirement.

## Source provenance

| Input | Exact revision | Purpose |
| --- | --- | --- |
| Existing Opamine | `1cabcbf0df1a552e3794a75f4b125ebe0a20a1dc` | Previous merged fork |
| Runtime recovery snapshot | `2e2ebab` | Preserve all September uncommitted fixes before integration |
| RootHide 3 | `24ea745b33cd3a1eba9b7196a875e42eed1fa34e` | Upstream `3.x` integration target |
| Dopamine release beneath RootHide | `13b26789842922cd4bd9fb5f30b3878d7e67ff0b` | Dopamine 3.0.12 |
| XPF | `9e12b8faa7444f6fe7f699aec6b6c96d151455d3` | Upstream offsets and patchfinder |
| litehook | `4f062946a964575694878130acecb7c990baba38` | Upstream symbol resolver and hook interface |
| opainject | `0068566501f3ddd04830f1ef0f1b74a8d1512281` | Standalone upstream injector build |

## Integration decisions

| Boundary | Upstream behavior retained | Fork behavior preserved or adapted |
| --- | --- | --- |
| Library ownership | The former `libjailbreak/src/roothider` core runtime moves to `BaseBin/libroothider/src`; launchdhook and systemhook retain their integration roles | Custom policies and strict BaseBin CDHash generation move with their owner; inactive duplicate source is removed |
| Launchd and IPC | Dopamine 3 message shapes, hookd provider, new check-in fields | Exact bundle/path selection, restricted blacklisted check-in, transactional hidden environment handoff |
| Systemhook | Inline dyld fallback, common subdirectory, hookd memory support, newer dyld APIs | Coherent hider/rebinding modules, selected-tweak state machine, environment scrub ordering, bounded phase attestation |
| Protected writes | Upstream hookd provider on newer OS versions | Rebinding uses hookd on iOS 19+ and verifies slot readback without falling back to direct writes after a rejected request |
| Root filesystem | RootHide primary and secondary randomized roots | Ownership validation, nested `.jbroot` inventory, post-move relative-link validation, guarded rollback |
| Trust caches | Upstream trust/check-in interfaces | All mappable final hashes, deduplication, fixed-UUID replacement completeness, bounded publish/readback/rollback semantics |
| Required images | New `libroothider.dylib` dependency | Six critical images required, including the selected dyldhook variant; uploaded hashes verified |
| Failure recovery | New launchd startup flow | Loader error details, log sharing, full reboot recovery, bounded ambiguous-injection wait |
| Packages | Updated upstream manager and Zebra | Fork Sileo has no URL scheme registrations; fork core package version remains protected |
| Update eligibility | Dopamine 3 release handling | Local BaseBin digest/build-ID detection and RootHide revision ordering; remote installation links stay within the Opamine fork |
| CI | New build dependencies and source layout | Workflow builds the current fork/ref using Xcode 16.4; upstream's hardcoded checkout workflow is excluded |

The build must package the real `libroothider.dylib`. The temporary stub exists only to break the circular library link dependency. An Xcode-only application build is insufficient to validate the embedded BaseBin.

Astra and Daybreak Blue reviewed the integration independently. Their findings drove the hookd permission-preservation fix, bounded launchd-injection recovery, required-image checks, and restoration of the XPF update-finalization guards. Implementation workers handled the application, core runtime, and test contracts; the parent reviewed the shared boundaries and reran integration checks.

## Evidence and findings

### E-001: Upstream identity

- observed_at: 2026-10-25
- source_type: command
- source_ref: upstream Git objects and remote refs
- content_hash: n/a
- artifact_path: n/a
- repro_command: `git ls-remote https://github.com/roothide/Dopamine-roothide.git HEAD refs/heads/3.x`
- raw_excerpt: `24ea745b33cd3a1eba9b7196a875e42eed1fa34e refs/heads/3.x`
- linked_workitem: n/a
- supersedes: none

### E-002: Required dependency transition

- observed_at: 2026-10-25
- source_type: file
- source_ref: upstream `BaseBin/roothidehooks/Makefile` and `BaseBin/libroothider/Makefile`
- content_hash: n/a
- artifact_path: n/a
- repro_command: `git show 24ea745:BaseBin/roothidehooks/Makefile`
- raw_excerpt: `roothidehooks_LDFLAGS = -L../.build -ljailbreak -lbsm -lroothider`
- linked_workitem: n/a
- supersedes: none

### F-001: Upstream migration must preserve loader trust and root recovery together

- severity: high
- category: design
- status: candidate
- evidence_ids: [E-001, E-002]
- location: `BaseBin/libroothider/src/common.m`, `Application/Dopamine/Jailbreak/DOBootstrapper.m`, `BaseBin/systemhook/src/roothider_main.c`
- impact: A missing link, omitted final CDHash, or packaged link stub can still cause the direct loader failure observed on iOS 16.2.
- confidence: high
- repro_steps: Build the complete BaseBin and application, inspect the packaged dependency set, then exercise a fresh-boot target-device activation and subsequent launch.
- remediation: Preserve transactional root/cache behavior and verify the actual generated archive before the device acceptance pass.
- residual_risk: Host source/build checks cannot prove the target device's dyld, trust, or launchd state.

### P-001: Startup and failure recovery

- path_type: callflow
- start: Opamine begins jailbreak activation.
- goal: Complete activation or reach a recoverable full-reboot UI.
- steps:
  1. Validate/recover the owned paired roots and loader links — evidence: E-001 — finding: F-001.
  2. Build/upload the complete final BaseBin hash set, including `libroothider` — evidence: E-002 — finding: F-001.
  3. Enter launchd injection with ambiguous failure treated as reboot-required — evidence: E-001 — finding: F-001.
  4. Initialize upstream hookd/dyld support and the fork's custom injection subsystem in order — evidence: E-001 — finding: F-001.
  5. Complete activation or share the failure log and issue a direct full-device reboot — evidence: E-001 — finding: F-001.
- residual_risks: iPhone15,3/iOS 16.2 activation and all supported device/OS combinations require device validation.

## Verification procedure

Run from the repository root:

```sh
make -C BaseBin BUILD_STANDALONE=0 -j2
make -C Packages
make -C Application
bash Scripts/verify_dopamine3_baseline.sh
make -C BaseBin/systemhook/tests test
make -C BaseBin/libjailbreak/tests test
unzip -tq Application/Dopamine.tipa
```

Device acceptance requires a full reboot of the previously affected phone, installation of the verified artifact, successful activation, successful subsequent app launch, and checking both custom injection modes with enabled/disabled tweaks. A deliberate failure after launchd injection should retain the log-sharing and full-reboot controls. No device runtime result is claimed by this report.

## Verification results on 2026-10-25

| Check | Result and limit |
| --- | --- |
| Upstream ref readback | `HEAD` and `3.x` both remain `24ea745b33cd3a1eba9b7196a875e42eed1fa34e` |
| Runtime component build | `make -C BaseBin subprojects -o idownloadd BUILD_STANDALONE=0 ADDITIONAL_CFLAGS=-fmodules-cache-path=/tmp/opamine3-final-component-cache -j2` passed; this deliberately excludes the blocked Xcode target and does not produce a complete archive |
| dyldhook | All six variants compile and pass their self-contained-image checks |
| Packages | `make -C Packages` passed |
| Systemhook tests | 52 characterization checks passed, zero failed; host fixtures also passed, including the production persona-spawn and hookd permission contracts |
| libjailbreak tests | All six suites passed: trust-cache geometry, ABI/capabilities, TXM/signatures, transaction fault model, filesystem status, and critical BaseBin hash coverage |
| launchdhook update checks | Required-symbol/static-image/XPC-type contract and systemwide trust adapter contract passed; targeted launchdhook rebuild passed |
| Version ordering | The production NSString category compiled against host Foundation and passed revision ordering, legacy dotted formats, fork suffixes, overflow, malformed-input, and nil checks |
| Application contracts | All eight scripts passed, including 16 owned-root identity/recovery tests, cleanup, exploit metadata, update lifecycle, late failure, and package/privacy checks |
| Targeted application syntax | iPhoneOS arm64 ARC syntax checks passed for DOJailbreaker, DOBootstrapper, DOEnvironmentManager, DOUIManager, DOMainViewController, settings, and update controllers; incomplete-implementation errors enabled for the environment/bootstrap classes. This is syntax verification, not a full app link/archive |
| Combined baseline | Five failures, all for new images absent from the stale pre-merge `basebin.tar`; source, dependency, package, and host-test lanes pass |
| Known resolver limitation | Existing caller-relative `RTLD_SELF`/`RTLD_NEXT` fallback can remain relative to the wrapper frame for unprovable/two-level callers; this merge does not claim to resolve it |
| Full BaseBin and Application | Blocked by local Xcode destination availability, before a fresh TIPA can be produced |

The full BaseBin log is `/tmp/opamine3-basebin-20261025.log`; the independent component, dyldhook, package, and application logs are `/tmp/opamine3-basebin-components-verified.log`, `/tmp/opamine3-dyldhook-20261025.log`, `/tmp/opamine3-packages-20261025.log`, and `/tmp/opamine3-application-build-20261025.log`. A repeat component build first hit a stale clang module-cache/header-mtime error; the recorded successful run uses a fresh, task-specific cache rather than deleting shared Xcode caches.

Xcode 16.4 lists the iPhoneOS 18.5 SDK, and direct clang builds target `LC_BUILD_VERSION: IOS`, but both idownloadd and Dopamine reject `generic/platform=iOS` with `iOS 18.5 is not installed`. Building without an explicit destination selected Mac Catalyst, so that attempt was rejected as device-build evidence. No platform download or device operation was performed. Restore a usable iOS platform installation before rerunning the complete build and artifact acceptance checks. Existing `basebin.tar` and TIPA files are stale outputs from before this integration; the baseline verifier correctly reports missing new images in the stale archive. Do not install them as this merge's output.

The unchanged stale outputs are identifiable by SHA-256: `basebin.tar` is `70a852099d25cdd52afc540c88c1c71d21fa98bb3af3b05874fea14964681543`; `Dopamine.tipa` is `4f64c2821c4d645f3e3e9da095cd53319353d6e9aed5ce5e54903d6192d9d7ec`. These hashes identify prior artifacts, not a release produced by this merge.

The hookd integration now reads the original leaf mapping permissions, refuses cross-mapping requests, temporarily writes without executable permission, and restores the original permissions even on write failure. Rebinding reports success only after checking both the pointer value and restored page permissions. Host tests exercise those production functions with Mach VM stubs; they do not establish behavior on a protected device.

The launchd injection phase uses one 45-second deadline for opainject completion and the boomerang acknowledgement. The receiver owns its context and semaphore independently of the waiting caller. An ambiguous failure enters the existing log-sharing and full-reboot recovery flow.

The application keeps the checked root-helper allocation, pipe, spawn, resume, cleanup, and exit-status paths. Protocol selection reads the installed BaseBin version with numeric ordering. Root-discovery methods remain in the active RootHide category in `DOBootstrapper.m`; the old rootless implementations remain intentionally commented out. Their declarations are separated into category headers, and source contracts verify the active category methods. `DOEnvironmentManager` also treats incomplete main-class implementations as compiler errors. The retained boot-logo picker retains its photo-library usage description.

The restored `roothide.deb` has no missing payload paths or regular-file hash differences compared with the new bootstrap's core payload. Its retained fork revision is `0.1.0-0+opamine1`; the bootstrap status advertises `0.1.0`. This package is distinct from the newly split `libroothider.dylib` runtime library.

Local environment updates use the BaseBin digest, then build ID, before falling back to release-version ordering. The remote release feed and installation links target `m1337v/Opamine`, so an in-app update cannot offer the upstream stock package as a fork upgrade. The fork's rolling `rhinject` release tag has no numeric version; it therefore does not advertise a numeric automatic update. Manual fork artifact updates and local BaseBin identity checks remain available.

### Upstream offset issue requiring device evidence

Upstream commit `96ab1786f47bc3a2f607c93b3f01f1d4ac8e423f` labels an inner proc_ro adjustment as iOS 26.5+, but repeats the outer Darwin `25.4.0` threshold. Astra flagged this as a possible premature offset adjustment on 26.4. The upstream threshold is retained pending kernel evidence for both releases; comments alone are insufficient to establish replacement offsets. No iOS 26.4/26.5 runtime compatibility is claimed. This issue does not select that branch on the affected iOS 16.2 phone.

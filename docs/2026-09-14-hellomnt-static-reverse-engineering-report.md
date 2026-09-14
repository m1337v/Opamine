# HelloMnt 1.2.2 Static Reverse-Engineering Report

- Date: 2026-09-14
- Package: `cn.zqbb.hello.mnt`
- Repository entry: `https://apt.002599.xyz` (redirect/chooser for `https://rootless.002599.xyz`)
- Artifact: `https://rootless.002599.xyz/rootless/cn.zqbb.hello.mnt_1.2.2_iphoneos-arm64e.deb`
- Package SHA-256: `3df40e2bcc485887dd071022db493557c685bd96424629bd9b0846bf6e2ffe83`
- Assessment type: static-only Mach-O and package analysis
- Status: evidence/reference; not approved for inclusion in Opamine

## Scope

Determine what zqbb's obfuscated HelloMnt package does, how Relaxin uses it,
whether it mounts a disk image, and whether any design is beneficial to the
Dopamine 3 to Opamine RootHide migration.

No package binary was executed. There was no authorized disposable iOS device
session in this pass, so runtime state, decrypted strings, and notification or
preference keys were not observed dynamically.

## Executive finding

HelloMnt is not a DMG or APFS-image mounting system. The strongest supported
interpretation is a privileged, general-purpose read-only mount manager built
for `bindfs`:

- a root launch daemon maintains and replays mounts;
- an unsandboxed/setuid app provides the mount-list UI and client functions;
- a MobileSubstrate dylib injected into `watchdogd` spawns and waits for a
  jailbreak-root helper, consistently with automatic remounting;
- Relaxin calls `HelloMntDaemon remountAll` after its first-run marker exists.

`bindfs` aliases one existing directory tree at another path. It does not create
or attach a block device. The binaries import `mount`, `unmount`, and
`getmntinfo`, carry `com.apple.private.bindfs-allow`, and contain no evidence of
DiskImages, `hdiutil`, APFS volume management, or image/device attachment. The
filesystem-type string is decoded at runtime, so static analysis supports but
does not literally expose the `"bindfs"` argument.

The apparent end-user use case solves two related problems: customize a normally
sealed system directory through a jailbreak-root shadow and present it at the
original system path; then restore the mount after reboot/watchdog lifecycle
events. The exact source-to-destination mapping is still an inference, not a
recovered binary contract. Its useful idea is idempotent reconciliation of a
small, declared set of required mounts. Opamine already has a scoped version of
the underlying mechanism for its fake `/usr/lib`; importing HelloMnt itself
would add a large privileged and obfuscated attack surface.

## Acquisition and package evidence

| Field | Value |
| --- | --- |
| Package | `cn.zqbb.hello.mnt` |
| Name | HelloMnt |
| Version | 1.2.2 |
| Architecture | `iphoneos-arm64e` |
| Installed size | 3172 KiB |
| Description | `Relaxin 挂载器!` (Relaxin mounter) |
| Maintainer/author | zqbb |
| Package SHA-256 | `3df40e2bcc485887dd071022db493557c685bd96424629bd9b0846bf6e2ffe83` |

The repository index also retains version 1.2.1 (SHA-256
`43f6ad2b1e6bc92498c4df2ffb89b5e56634848fc76ac16409349a8f789833c7`).
Version 1.2.2 is the newest indexed build and is the subject of this report.
The repository publishes no verifiable `InRelease` or `Release.gpg` signature,
and the package declares no dependencies, conflicts, or replacements. Hashes
establish which bytes were analyzed; they do not establish trust in the
publisher.

Payload:

| File | Role | SHA-256 |
| --- | --- | --- |
| `/usr/bin/HelloMntDaemon` | root mount/reconciliation daemon | `8be532c12b357eda2e51c9cf0615cb7d5793bf8211d767607407c64adf2849bf` |
| `/Applications/HelloMnt.app/HelloMnt` | UI and privileged client | `d3e090ae9d3e05c9e4cdbe9866bd45ef17e48b3dba0cd78ef48335c5ec4ad5a5` |
| `/Library/MobileSubstrate/DynamicLibraries/HookToRemountAll.dylib` | watchdogd lifecycle hook | `26cb0d19960f2c3566d97893012d03bdbff24a60bdc00e810c31b85f74ad3f1d` |
| launch daemon plist | root daemon registration | `f7612c5b59c252b6b8feaef3c86c9c8b12311ecc92dd31350acce451efa141e1` |
| substrate filter plist | targets `watchdogd` | `d635927e249330e8511f17ebaeb98b718e29b39ec83ccfc0aa2d27fad75a3040` |

All three payload Mach-Os are universal arm64/arm64e, have minimum iOS 15, and
were linked with the iOS 16.4 SDK. Their encryption load commands report
`cryptid=0`; the analyzed code is not App Store-encrypted. They contain embedded
entitlement blobs, but host `codesign` reports no valid signing identity.

The launch daemon has `KeepAlive=true`, `RunAtLoad=true`, user `root`, and
program `/usr/bin/HelloMntDaemon`.

## Entitlements and privilege model

The daemon and app include:

- `platform-application`;
- no sandbox/container requirement;
- AppBundles and AppDataContainers storage access;
- `com.apple.private.bindfs-allow=true`;
- AGX and IOSurface IOKit user-client access.

The maintainer executables include platform status, no-container, and skipped
library validation. The installer changes the app executable to root:wheel and
mode `07755`, then loads the daemon with `launchctl`. The removal executable
unloads the daemon.

Mode `07755` enables set-user-ID, set-group-ID, and the sticky bit in addition
to normal execute permissions. Combined with an unsandboxed platform binary,
this is a high-risk privilege boundary for a UI that accepts paths.

## Static behavior

### Daemon

The daemon imports:

- `mount`, `unmount`, `getmntinfo`;
- `copyfile`, Foundation filesystem APIs, and `access`;
- CoreFoundation Darwin notification registration and posting;
- `posix_spawn`, `waitpid`, `dlopen`, and `dlsym`;
- `jbroot` for randomized-root path resolution;
- `memorystatus_control`.

It exports `HMPrepareDestination`. Direct mount calls at `0x10000b330` and
`0x10001a410` set flags to `MNT_RDONLY`; direct unmount calls at `0x1000158a0`
and `0x100016480` use `MNT_FORCE`. The mount source and destination are computed
from state. The exact filesystem-type string is obfuscated, but the dedicated
`bindfs-allow` entitlement, XNU mount contract, publisher UI, and absence of an
alternative image-mounting framework make `bindfs` the high-confidence
interpretation.

`HMPrepareDestination`, `copyfile`, and filesystem mutation calls indicate a
preparation step for the destination or a shadow tree before mounting. Static
analysis does not prove the exact copy direction for every command, so this is
not treated as a recovered source-level contract.

### App

The app exports:

- `HMAddMountPath`;
- `HMLoadJailbreak`;
- `HMStoredMountPaths`;
- `HMUnmountPath`.

UI symbols include a path field, selected path state, and independent unmount
and remove actions. This supports a persistent user-entered path list rather
than a single hard-coded Relaxin system mount; static analysis did not recover
its path validation. It uses Darwin notifications and semaphores to coordinate
with the daemon.

The publisher's [depiction screenshot](https://rootless.002599.xyz/web/assets/cn.zqbb.hello.mnt/1.PNG)
offers `/System/Library/Fonts` as a common path and shows
`/System/Library/Fonts/Watch` in the mounted list. It tells the user that a
long-press opens the location in Filza. Together with `HMPrepareDestination` and
`copyfile`, this is strong behavioral evidence for the practical use case: make
a shadow copy of a sealed system directory, let the user edit the shadow, and
mount it over the original path. The exact internal shadow path, copy direction,
and decoded mount arguments remain obfuscated and were not recovered statically.

### Watchdog hook

The substrate filter targets only `watchdogd`. The dylib resolves a jailbreak
root path, builds a process argument vector, spawns a helper, and waits for it.
Together with the Relaxin call site, package naming, and publisher changelog,
the high-confidence role is automatic remounting at a watchdog/userspace
lifecycle boundary. The hook's decoded helper path and argv are not statically
proven to be `HelloMntDaemon remountAll`.

### Relaxin integration

The [public w2599 tree](https://github.com/w2599/Relaxin/blob/main/RelaxinEngine/Stages/Runtime/RLXSystemHookActivationTask.m#L175-L188)
calls `setCustomMount` during system-hook activation:

1. On first run, create `JBROOT/mnt/.zqbbJailbreak`.
2. On later runs, if `JBROOT/usr/bin/HelloMntDaemon` exists, execute
   `HelloMntDaemon remountAll`.

The first-run marker avoids immediately replaying a mount list before the
companion package has been configured. It does not reveal which paths a user or
release package adds to HelloMnt's persistent list.

The daemon imports no `xpc_*`, Mach/bootstrap, or `notify_*` APIs. Its use of
CoreFoundation notifications plus property-list/dictionary file APIs indicates
that notification wakeups and shared file-backed state are more likely than a
custom XPC service. Exact notification names, state path, and keys are runtime
decoded.

## Obfuscation assessment

The daemon has no normal plaintext `__cstring` section for its operational
strings. Its major functions use indirect `br xN` dispatch, large state tables,
opaque arithmetic predicates, many small helper stubs, and runtime string
construction. IDA and radare2 both reduce `main` and `HMPrepareDestination` to
computed-branch state machines rather than reliable structured pseudocode.

Only one direct daemon `strcmp` was found; it compares an argv-derived value
against runtime-decoded data. This is consistent with narrow command dispatch
such as Relaxin's `remountAll`, but it does not expose the command token. The
app and hook use the same techniques for paths, notifications, and spawn argv.
The report therefore relies on cross-evidence from imports, entitlements,
call-site arguments, UI, package metadata, and public Relaxin integration rather
than pretending the obfuscated binary was recovered as source.

## Why this is bindfs rather than a DMG

Apple's `bindfs` mount takes an existing lower-directory path as mount data and
exposes it at a second mount point. The XNU implementation marks it read-only,
non-browsable, no-suid, and multilabel. It checks the private bindfs entitlement.
See the [XNU bindfs VFS implementation](https://www.newosxbook.com/src.php?file=/bsd/miscfs/bindfs/bind_vfsops.c&tree=xnu).

The observed HelloMnt contract matches this exactly:

| Evidence | bindfs | DMG/APFS image |
| --- | --- | --- |
| `com.apple.private.bindfs-allow` | Required | Irrelevant |
| `mount` source is a path pointer | Expected | Insufficient |
| Direct `MNT_RDONLY` mounts | Expected | Possible but not distinctive |
| `getmntinfo` reconciliation | Expected | Possible |
| DiskImages/APFS/device APIs | Not needed | Expected evidence, absent |
| Persistent list of paths | Natural fit | Does not identify images/devices |

Confidence: high that HelloMnt is designed for `bindfs`; high that its use case
includes replaying path mounts after lifecycle events; medium on the exact
source/destination and preparation/copy details because string and control-flow
obfuscation prevent a complete source-level reconstruction.

## Relationship to existing Opamine code

Opamine already prepares `JBROOT/basebin/.fakelib` by copying `/usr/lib`, then
replacing its `dyld` and adding `systemhook.dylib`. `jbctl` mounts that directory
read-only over `/usr/lib` using `bindfs` and force-unmounts it when necessary.

There is also an existing, currently commented-out `ensure_fakelib_mounted`
path in `BaseBin/launchdhook/src/spawn_hook.c`. Its comment describes the same
problem HelloMnt addresses: a hidden jailbreak has no fake-library mount, but
launchd needs it restored to regain code execution after a userspace reboot.

Therefore HelloMnt does not introduce a new filesystem primitive. It generalizes
and externalizes an already present Dopamine lifecycle mechanism.

## Security and reliability assessment

| Finding | Severity | Consequence |
| --- | --- | --- |
| User-entered path management through privileged UI | High | Unresolved validation mistakes can expose or cover sensitive trees. |
| Root, KeepAlive daemon | High | Persistent privileged attack and failure surface. |
| App executable changed to `07755` root:wheel | High | Unusually broad privilege boundary for UI code. |
| Injection into `watchdogd` | High | A hook failure can affect a critical lifecycle daemon. |
| Force-unmount behavior | Medium | Can disrupt live users if state detection or ordering is wrong. |
| Obfuscated control flow and strings | Medium | Prevents normal review, maintenance, and reproducible trust. |
| General persistent mount list | Medium | Stale or conflicting entries can be replayed across boots. |
| RootHide-aware `jbroot` use | Positive | Avoids a fixed `/var/jb` assumption. |
| Read-only mounts and state inspection | Positive | Reduces write exposure and enables idempotence. |

No malware conclusion is asserted. The issue is that this privilege level and
obfuscation make the binary unsuitable as a trusted Opamine component without
source, reproducible builds, and a much narrower contract.

## Recommendation

Do not bundle, invoke, or copy HelloMnt. Do not expose arbitrary mount paths and
do not add another root daemon or watchdogd hook.

If device testing proves the current fake-library mount can be lost during a
supported userspace-reboot/hide sequence, implement only the useful pattern in
auditable Opamine code:

1. Define a compile-time allowlist of Opamine-owned mount descriptors containing
   canonical source, destination, flags, and required lifecycle phase.
2. Resolve the randomized jailbreak root through existing RootHide APIs.
3. Validate source and destination ownership, type, symlink traversal, and
   expected filesystem identity.
4. Inspect `getmntinfo` and reconcile idempotently; never stack duplicate mounts.
5. Mount only `bindfs` with the minimum flags; fail closed on mismatched existing
   mounts.
6. Restore only at the launchd lifecycle seam already responsible for fakelib.
7. Unmount in reverse dependency order before hide, update, or removal.
8. Keep policy and lifecycle state in existing jbserver/launchdhook ownership;
   do not introduce a user-editable registry.
9. Log source/destination hashes or canonical identities without leaking the
   randomized root to untrusted processes.
10. Add fault-injection and device tests before enabling the path.

This should be a narrow `fakelib` mount-state reconciler, not a generic mount
framework. If the commented existing remount path can be corrected safely, it
is the preferred integration seam.

## Verification path

Before any implementation:

1. Reproduce a supported userspace reboot while hidden and visible.
2. Record `/usr/lib` mount identity before, during, and after the transition.
3. Confirm whether current launchd code execution is actually lost.
4. Determine why the existing `ensure_fakelib_mounted` path was disabled.
5. Test a narrow restoration patch on arm64 and arm64e, including iOS 15.
6. Verify blacklist/allowlist/hidden-injection behavior and clean removal.

Optional deeper reverse engineering should use a disposable test device with
filesystem and process-spawn tracing. Observe daemon arguments, Darwin
notifications, persisted mount records, and `mount`/`unmount` parameters. Do not
run the package on a daily-use device merely to recover obfuscated strings.

## Timeline

1. Completed: package acquisition, hashing, metadata, payload, entitlements,
   imports/exports, installer/remover, call-site, and Relaxin-source analysis.
2. Pending only if needed: disposable-device runtime tracing of preference keys,
   notification names, and exact preparation semantics.
3. Product gate: demonstrate a real Opamine fakelib restoration defect.
4. If proven: implement the narrow existing-lifecycle reconciler and run the
   full device matrix.

## Evidence limitations

- Heavy control-flow flattening and encrypted/constructed strings prevent exact
  static recovery of all commands and persistence keys.
- No dynamic execution or device tracing occurred.
- Package provenance was verified by repository acquisition and hashes, not by
  reproducible source or a maintainer signature chain. The repository metadata
  itself is unsigned.
- Conclusions distinguish direct static facts from high-confidence inference;
  uncertain preparation internals are not treated as requirements.

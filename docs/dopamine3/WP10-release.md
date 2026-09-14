# WP10 UI and package finalization status

Date: 2026-09-14

Status: host/mechanical work complete for the bounded WP10 slice; device and
release gates remain open.

## Implemented

- The settings action for direct jailbreak removal is now shown only when the
  environment is inactive, bootstrapped, and installed through TrollStore.
  A live randomized RootHide root must use the reboot/rejailbreak removal
  flow, so the UI no longer exposes the unsafe direct-delete action while
  jailbroken.
- `check_wp10_ui_package_contract.py` checks that removal gate, the existing
  Opamine bundle identity and support strings, package source/version pins,
  embedded Sileo metadata, and the stripped Sileo URL-registration keys.
- `verify_dopamine3_baseline.sh` now treats `1b40dbdb17ff60e106d91ce87c0da249923aa31f`
  as an immutable ancestor to inspect, rather than requiring it to remain the
  current `HEAD`. It checks the intended D3 dependency checkouts:
  ChOma/nested ChOma `7dccded6…`, litehook `0d9d17af…`, and the local RootHide
  XPF integration `1e5da55f…`.

## Identity, support, and package invariants

The Opamine bundle identifier remains `com.opa334.Dopamine-roothide`. The
advertised source matrix remains iOS 15.0–16.5.1 on arm64e and iOS
15.0–16.7.16 on arm64; no new device or exploit support is claimed by WP10.

RootHide Core remains `0.1.0-0+opamine1` and Sileo remains
`2.5.1-13+opamine1`. Their source hashes and package transformations remain
owned by `Scripts/build-fork-packages.sh`. The embedded Sileo
`CFBundleURLTypes` and `CFBundleURLSchemes` keys remain absent; its observed
`filza` query permission is retained.

## Release-version gate

The Dopamine 3 2.x-to-3.x update guard is version-sensitive. The separately
owned `BaseBin/_external/basebin/.version` must be set to a value strictly
greater than official 3.0.9 before creating a release artifact; the planned
Opamine value is `3.0.9.1`. At this capture, the in-progress checkout still
reports `3.0.9.1`; the WP10 contract test and
`REQUIRE_RELEASE_VERSION=1 ./Scripts/verify_dopamine3_baseline.sh` enforce that
gate. Do not package a 2.4.x value after adopting the D3 ABI, because it can
bypass the hard-reboot transition guard.

## Deferred gates

- The official 3.0.9 icon-cache rebuild on iOS 18.4+ is not included here. It
  requires coordinated changes in the protected `DOEnvironmentManager`,
  `DOJailbreaker`, and `jbctl` paths; adding only a UI label would be
  misleading and would not prove removal behavior.
- Clean install, RootHide upgrade, Opamine upgrade, userspace/full reboot,
  retry, update, remove, package-manager reinstall, and broken-root recovery
  still require arm64/arm64e device runs. Host/source contracts do not claim
  those gates passed.

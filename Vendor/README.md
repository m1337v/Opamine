# Vendored Sileo

Opamine builds its Sileo package from the pinned `Sileo` submodule, using
`m1337v/Sileo-roothide`. It does not download or patch a Sileo release binary.
The generated `Application/Dopamine/Resources/sileo.deb` is intentionally ignored
by Git and must exist before Xcode processes the app's resource references.

`sileo.lock.json` records the exact fork and RootHide upstream commits, package
version, bundle identity, and app marketing version. The current source is
RootHide Sileo **2.5.1-14**, packaged as **2.5.1-14+opamine1**. RootHide's
`iphoneos-arm64e` Debian architecture is a bootstrap/package convention; the
upstream Sileo build intentionally produces an arm64 iOS executable.

## Intended difference

The only application-code difference from the pinned upstream commit is
`Sileo/Info.plist`. Structurally, that plist differs
only by removal of URL registration keys (`CFBundleURLTypes`, including its
nested `sileo` scheme). `LSApplicationQueriesSchemes`, including `filza`, document
types, bundle identity, and all other settings remain unchanged. The builder
checks this invariant against the actual pinned Git objects. A separate,
exactly checked Xcode per-file flag disables the `strrchr` builtin for
`dpkgversion.c`: optimized builds otherwise reference an unavailable `memrchr`
symbol. The upstream C comparator and its behavior remain unchanged. No other
source or project differences are permitted outside GitHub workflows.

The updated fork replaces its stale build workarounds with upstream's versions
and removes an obsolete generated `data.tar.xz`. Fork workflows retain their own
publishing setup and use the `+opamine1` Debian package revision.

## Build and verify

```sh
git submodule update --init --recursive
python3 Scripts/build_vendored_sileo.py --verify-source
make -C Application
python3 Scripts/build_vendored_sileo.py --verify-package Application/Dopamine/Resources/sileo.deb
```

The normal and nightly Application targets both require the generated package.
The builder exports the pinned source to a temporary directory and uses a
separate `.build/sileo` cache. SwiftPM can normalize its lock-file format in that
export, but its dependency repository/revision set must remain unchanged. The
vendored checkout itself stays clean.

An export-only Makefile adapter selects `generic/platform=iOS` and passes the
upstream architecture through the `ARCHS` build setting. This avoids both
Mac Catalyst fallback and Xcode's incompatible `-arch`/`-destination` options.
The package verifier checks the executable's actual iOS platform, Debian
identity/version/architecture, app identity/version, root-helper mode, absent
URL registrations, and unchanged query schemes. A build or validation failure
does not replace the existing package, and Make stops instead of using it.

## Updating the pin

1. Merge the desired RootHide Sileo revision into `m1337v/Sileo-roothide`.
   Preserve the one plist customization and compare the complete application
   source tree against upstream. Keep dependency lock files and upstream
   build fixes intact.
2. Set the fork workflow's package revision, update `sileo.lock.json`, and point
   the submodule at the published fork commit. Keep the bundled Sileo version
   in `DOBootstrapper.m` aligned; the contracts reject a mismatch.
3. Run the source checks, host contracts, full build, and generated-package
   verifier. Inspect the exact commit's Actions run and final TIPA contents.
   Source/package checks do not establish behavior on an iOS device.

The former `Scripts/build-fork-packages.sh` entry point now delegates Sileo to
this source builder. Its separately pinned RootHide Core repack remains intact.

# Opamine-RH Build Guide

## Prerequisites

| Tool | Location | Purpose |
|------|----------|---------|
| **Xcode 16+** | `/usr/bin/xcodebuild` | Builds `Dopamine.app` (iOS target) |
| **iOS SDK** | Ships with Xcode (iPhoneOS SDK) | `xcrun --sdk iphoneos --show-sdk-path` |
| **theos** | `$THEOS` (default: `~/theos`) | Builds `opainject` and `roothidehooks` subprojects |
| **ldid** | `$(brew --prefix)/bin/ldid` | Ad-hoc codesigning for dylibs and the app |
| **trustcache** | `BaseBin/trustcache` OR `../../Opamine-dopamine/BaseBin/trustcache` OR `$PATH` | Generates `basebin.tc` trust cache |
| **libarchive** | `$(brew --prefix)/opt/libarchive` | Required by `libjailbreak` (archive extraction) |
| **dpkg-deb** | `$(brew --prefix)/bin/dpkg-deb` | Builds `.deb` packages in `Packages/` |

### Install missing tools

```bash
# homebrew packages
brew install ldid libarchive dpkg

# theos (if not installed)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
```

### Environment

```bash
export THEOS=~/theos         # adjust if theos is elsewhere
export PATH="$THEOS/bin:$PATH"
```

---

## Quick Build (full TIPA)

```bash
cd /Users/a1337/Downloads/dev/_JB/roothide/JB/Opamine-rh

# Set theos
export THEOS=~/theos
export PATH="$THEOS/bin:$PATH"

# Full build: BaseBin + Packages + Application
make full
```

Output: `Application/Dopamine.tipa` (~54 MB)

---

## Step-by-Step Build

### 1. Build BaseBin (`basebin.tar`)

```bash
make basebin
```

This runs (in order):
1. `ChOma` → `libchoma.dylib` (Mach-O parsing library)
2. `XPF` → `libxpf.dylib` (XNU patchfinder)
3. `MachOMerger` → `MachOMerger` binary
4. `opainject` → `opainject` binary (uses theos)
5. `libjailbreak` → `libjailbreak.dylib` (core JB library)
6. `systemhook` → `systemhook.dylib` (DYLD_INSERT hook)
7. `forkfix` → `forkfix.dylib`
8. `launchdhook` → `launchdhook.dylib` (launchd spawn interceptor)
9. `boomerang` → `boomerang` binary
10. `jbctl` → `jbctl` binary
11. `idownloadd` → `idownloadd` binary
12. `watchdoghook` → `watchdoghook.dylib`
13. `roothidehooks` → `roothidehooks.dylib` (uses theos)
14. `bootstrapper` → `bootstrapper` binary
15. `jailbreakd` → `jailbreakd` binary
16. `trustcache create` → `basebin.tc`
17. `dyldhook` → `dyldhook-*.dylib` (built AFTER trustcache, not included in it)
18. `tar` → `basebin.tar` (packages `.build/` contents)

Output: `BaseBin/basebin.tar`

### 2. Build Packages (`.deb` files)

```bash
make packages
```

Builds three `.deb` packages:
- `Packages/libkrw-provider/libkrw-dopamine.deb`
- `Packages/libroot/libroot.deb`
- `Packages/basebin-link/basebin-link.deb`

These are embedded into `Dopamine.app` during the Application build.

### 3. Build Application (`Dopamine.tipa`)

```bash
make -C Application
```

This:
1. Runs `xcodebuild` to compile `Dopamine.app` (Xcode project in `Application/Dopamine.xcodeproj`)
2. Copies `basebin.tar` and `basebin.tc` into the app bundle
3. Copies `.deb` packages into the app bundle
4. Builds `palera1n` exploit framework
5. Signs with `ldid`
6. Creates `Dopamine.ipa` (zip of `Payload/Dopamine.app`)
7. Copies to `Dopamine.tipa`

Output: `Application/Dopamine.tipa`

---

## Incremental Builds

After modifying only BaseBin sources (e.g., `systemhook`, `launchdhook`, `libjailbreak`):

```bash
# Rebuild only the changed subproject + repackage
make -C BaseBin/systemhook       # rebuild systemhook.dylib
make -C BaseBin/launchdhook      # rebuild launchdhook.dylib
make -C BaseBin basebin.tar      # repackage basebin.tar (re-runs trustcache + tar)
make -C Application              # repackage TIPA with new basebin.tar
```

Or simply:

```bash
make   # rebuilds basebin then tipa (make detects changes)
```

### Rebuild a single subproject

```bash
# systemhook (raw clang, no theos)
make -C BaseBin/systemhook

# launchdhook (raw clang, no theos)
make -C BaseBin/launchdhook

# libjailbreak (raw clang, no theos)
make -C BaseBin/libjailbreak

# roothidehooks (theos-based)
make -C BaseBin/roothidehooks

# opainject (theos-based)
make -C BaseBin/opainject FINALPACKAGE=1
```

---

## Clean Build

```bash
make clean   # cleans BaseBin, Packages, Application
make full    # full rebuild
```

---

## Verify Build Integrity

```bash
# Hashes must match — confirms basebin.tar inside TIPA is the same as built
md5 -q BaseBin/basebin.tar
unzip -p Application/Dopamine.tipa Payload/Dopamine.app/basebin.tar | md5 -q
```

---

## Deploy to Device

### Full update (TIPA via TrollStore)

```bash
make update DEVICE=root@<IP>
```

This:
1. Builds everything
2. SCPs `Dopamine.tipa` to device
3. Runs `jbctl update tipa <path>` on device
4. Device performs userspace reboot with new binaries

### BaseBin-only update

```bash
make update-basebin DEVICE=root@<IP>
```

Faster — only updates basebin without rebuilding the full app.

---

## Build System Architecture

```
Makefile (root)
├── make basebin → BaseBin/Makefile
│   ├── .build/     (staging directory, recreated each build)
│   ├── .include/   (collected headers from subprojects)
│   ├── subprojects (ChOma → XPF → ... → jailbreakd)
│   ├── basebin.tc  (trustcache from .build/)
│   ├── dyldhook    (built after trustcache)
│   └── basebin.tar (tar of .build/)
├── make packages → Packages/Makefile
│   ├── libkrw-dopamine.deb
│   ├── libroot.deb
│   └── basebin-link.deb
└── make tipa → Application/Makefile
    ├── xcodebuild (Dopamine.xcodeproj)
    ├── palera1n exploit framework
    ├── copy basebin.tar + .debs into app bundle
    ├── ldid signing
    └── zip → Dopamine.ipa → cp → Dopamine.tipa
```

### Dependency chain

```
ChOma → XPF
ChOma → libjailbreak → systemhook → forkfix
                     → launchdhook
                     → boomerang, jbctl, idownloadd
                     → watchdoghook, roothidehooks
                     → jailbreakd, bootstrapper
all subprojects → trustcache → dyldhook → basebin.tar
packages (independent of BaseBin)
basebin.tar + packages → Application → Dopamine.tipa
```

### Compiler usage

| Subproject | Compiler | Notes |
|-----------|----------|-------|
| systemhook | raw `clang` | Dual-arch arm64+arm64e, `-Os` |
| launchdhook | raw `clang` | Dual-arch, ObjC ARC, `-O2` |
| libjailbreak | raw `clang` | Dual-arch, ObjC ARC, links libarchive |
| opainject | **theos** | `$THEOS` must be set |
| roothidehooks | **theos** | `$THEOS` must be set, roothide scheme |
| Dopamine.app | **xcodebuild** | Xcode project, Debug-iphoneos config |
| palera1n | **theos** (inside Application build) | Built by Application/Makefile |

---

## Common Issues

### `trustcache binary not found`

The Makefile looks for `trustcache` in this order:
1. `BaseBin/trustcache` (local copy)
2. `../../Opamine-dopamine/BaseBin/trustcache` (sibling project)
3. `trustcache` in `$PATH`

Copy or symlink the binary: `cp ../Opamine-dopamine/BaseBin/trustcache BaseBin/`

### `CpResource failed: libroot.deb / libkrw-dopamine.deb`

Packages weren't built. Run `make packages` before `make tipa`, or use `make full`.

### theos not found / `$THEOS` not set

```bash
export THEOS=~/theos
export PATH="$THEOS/bin:$PATH"
```

### Xcode module cache errors

The Makefile includes a workaround:
```bash
find /var/folders -type d -path '*/C/clang/ModuleCache' -prune -exec rm -rf {} + 2>/dev/null || true
```

If builds fail with module-related errors, this runs automatically. You can also run it manually.

### `MARKETING_VERSION` / version

Version comes from `BaseBin/_external/basebin/.version` (currently `2.4.8.21`).

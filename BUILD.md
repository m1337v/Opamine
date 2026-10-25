# Opamine RootHide 3 build guide

The checkout used for this merge is:

```sh
cd /Users/a1337/Downloads/dev/_JB/roothide/Resources/Opamine-rh-refresh
```

## Build requirements

- Xcode 16.4 with the iOS 18.5 SDK and an installed iOS device platform.
- `xcodebuild`, `clang`, and Procursus `ldid`.
- A `trustcache` executable. `BaseBin/Makefile` searches `BaseBin/trustcache`, the sibling `Opamine-dopamine/BaseBin/trustcache`, then `$PATH`.
- `libarchive` for `libjailbreak` and `dpkg-deb` for the package targets.
- Theos for `rootlesshooks`, `roothidehooks`, and the bundled `palera1n` framework. `opainject` is a standalone clang target and does not use Theos.

Check the selected Xcode and SDK with:

```sh
xcode-select -p
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-version
xcodebuild -scheme Dopamine -showdestinations
```

The app and `idownloadd` builds select `-destination 'generic/platform=iOS'`. The iOS destination must be available in Xcode; seeing the SDK path alone is not enough.

## Build commands

The root Makefile defines `all`, `clean`, `update`, and `update-basebin`. The default `make` runs BaseBin, Packages, then Application:

```sh
make
```

The equivalent component commands are:

```sh
make -C BaseBin       # BaseBin/basebin.tar and BaseBin/basebin.tc
make -C Packages      # the three .deb packages
make -C Application   # Dopamine.ipa and a copy named Dopamine.tipa
```

There are no root targets named `full`, `basebin`, `packages`, or `tipa`; use the component-directory commands above. `make clean` cleans BaseBin, Packages, and Application outputs.

## RootHide 3 BaseBin layout

`make -C BaseBin` stages the runtime in `BaseBin/.build`, creates its trust cache, builds the dyld variants, and packages `BaseBin/basebin.tar`. The `libroothider` dependency cycle is intentional: `libroothider-stub.dylib` is staged first so `libjailbreak` can build; the full `libroothider.dylib` is then built and replaces the stub before the final trustcache and archive. `hookd` is also built into the runtime.

The dyld hook contributes six dylibs: arm64 and arm64e for iOS 15, iOS 16–17, and iOS 18+. These are added after trustcache generation, as configured in `BaseBin/Makefile`.

The application embeds `basebin.tar`, `basebin.tc`, the built `.deb` packages, and the full `libroothider.dylib`. Its version is assembled from the BaseBin version files as `3.0.12-28+opamine1`.

## Local platform status (2026-10-25)

This host reports Xcode 16.4 and the iOS 18.5 SDK, but Xcode marks both the connected iPhone and `Any iOS Device` destination as ineligible with “iOS 18.5 is not installed.” The available no-destination build resolves to Mac Catalyst, so it is not a device build. The generic iOS destination therefore still needs to be made usable on this host; no fresh TIPA build is claimed for this date.

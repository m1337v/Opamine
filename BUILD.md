# Opamine RootHide 3 build guide

The checkout used for this merge is:

```sh
cd /Users/a1337/Downloads/dev/_JB/roothide/Resources/Opamine-rh-refresh
```

## Build requirements

- Xcode 16.4 with the iOS 18.5 SDK and an installed iOS device platform.
- `xcodebuild`, `clang`, and Procursus `ldid`.
- `python3` and initialized Git submodules for the pinned Sileo source build.
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

## Vendored Sileo

Sileo is built from the `Vendor/Sileo` submodule at fork revision `cac1f2bde2ee6bb2b984a1cf99857ec79037fa0f`, with RootHide upstream pinned at `84645de5fee6edeb2a1ce5c4f8a97abf9755c5d1`. `Vendor/sileo.lock.json` records the source revisions, package identity, architecture, and package version. Initialize and validate the pinned checkout with:

```sh
git submodule update --init --recursive
python3 Scripts/build_vendored_sileo.py --verify-source
```

The Sileo builder exports the pinned source to an isolated build directory, resolves its locked Swift package dependencies, builds the `iphoneos-arm64e` package, and verifies it before copying it to `Application/Dopamine/Resources/sileo.deb`. It does not download a prebuilt Sileo package. `make -C Application` generates this file before Xcode builds the Dopamine app; the generated `.deb` is ignored by Git. The source check permits the URL-registration removal while requiring the upstream `LSApplicationQueriesSchemes` value to remain unchanged.

The expected Sileo Debian package is `org.coolstar.sileo` version `2.5.1-14+opamine1` for `iphoneos-arm64e`; its app marketing version remains `2.5.1-14`. Verify the generated package with:

```sh
python3 Scripts/build_vendored_sileo.py --verify-package Application/Dopamine/Resources/sileo.deb
```

## RootHide 3 BaseBin layout

`make -C BaseBin` stages the runtime in `BaseBin/.build`, creates its trust cache, builds the dyld variants, and packages `BaseBin/basebin.tar`. The `libroothider` dependency cycle is intentional: `libroothider-stub.dylib` is staged first so `libjailbreak` can build; the full `libroothider.dylib` is then built and replaces the stub before the final trustcache and archive. `hookd` is also built into the runtime.

The dyld hook contributes six dylibs: arm64 and arm64e for iOS 15, iOS 16–17, and iOS 18+. These are added after trustcache generation, as configured in `BaseBin/Makefile`.

The application embeds `basebin.tar`, `basebin.tc`, the built `.deb` packages, and the full `libroothider.dylib`. Its version is assembled from the BaseBin version files as `3.0.12-29+opamine1`.

## Local platform status (2026-10-25)

This host reports Xcode 16.4 and the iOS 18.5 SDK, but Xcode marks both the connected iPhone and `Any iOS Device` destination as ineligible with “iOS 18.5 is not installed.” The available no-destination build resolves to Mac Catalyst, so it is not a device build. The generic iOS destination therefore still needs to be made usable on this host; no fresh TIPA build is claimed for this date.

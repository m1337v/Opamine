# Fork-owned packages

Opamine bundles two reviewed packages that must not be replaced silently by
their unmodified repository variants.

- `org.coolstar.sileo` is based on RootHide's Sileo `2.5.1-13`. Opamine removes
  `CFBundleURLTypes` from `Sileo.app/Info.plist`, preventing registration of the
  detectable `sileo://` URL scheme, and publishes it as
  `2.5.1-13+opamine1`.
- `roothide` is based byte-for-byte on the official RootHide Core `0.1.0`
  payload and is published as `0.1.0-0+opamine1`. The reviewed update retains the
  existing exported ABI and includes upstream's `notify_dump_status` vroot shim.

The source URLs and SHA-256 pins are recorded in
`Scripts/build-fork-packages.sh`. Run that script on macOS to reproduce both
`.deb` files. Opamine compares package versions with `dpkg --compare-versions`
and upgrades an existing Sileo installation plus RootHide Core during bootstrap
finalization. A future upstream version will sort above these fork revisions and
must be reviewed before updating the pins.

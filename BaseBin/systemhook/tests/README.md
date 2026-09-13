# systemhook characterization lane

This directory contains small, host-runnable characterization checks for the
current rhinject systemhook contract.  They are intentionally separate from
the iOS build: the production sources include Darwin, Mach-O, Objective-C and
RootHide-only APIs which cannot be compiled faithfully by the host compiler.

The checks therefore have two parts:

* pure host doubles for deterministic contracts (token parsing, executable
  selection, hook/remap state, `dlsym` error semantics, sysctl two-pass
  behavior and directory state lifetime); and
* static assertions against the current production sources plus a JSON
  ownership matrix.

Passing this lane does **not** prove that an iOS hook is installed, that PAC or
dyld-private ABI behavior is correct, or that a detector is bypassed.  The
runner reports those production gaps as `known_gaps` instead of disguising
them as host-test coverage.

Run it from the repository root or from this directory:

```sh
make -C BaseBin/systemhook/tests test
make -C BaseBin/systemhook/tests json > /tmp/rhinject-systemhook-characterization.json
```

`ownership.json` is the machine-readable inventory intended to be handed to
implementation workers.  Every owner path and listed symbol is checked by the
runner so the inventory cannot silently drift.

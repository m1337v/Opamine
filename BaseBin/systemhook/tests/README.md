# systemhook characterization lane

This directory contains small, host-runnable characterization checks for the
current rhinject systemhook contract.  They are intentionally separate from
the iOS build: the production sources include Darwin, Mach-O, Objective-C and
RootHide-only APIs which cannot be compiled faithfully by the host compiler.

The checks therefore have three parts:

* pure host doubles for deterministic contracts (token parsing, executable
  selection, hook/remap state, callback replay/catalog ordering, `dlsym`
  error semantics, sysctl two-pass behavior and directory state lifetime); and
* static assertions against the current production sources plus a JSON
  ownership matrix; and
* a macOS-host executable fixture that includes the production `rhi_rebind.c`
  decoder and validates chained import metadata, addends, weak imports, PAC
  schema decoding, original-file chain words and malformed-precommit refusal.

Passing this lane does **not** prove that an iOS hook is installed, that PAC or
dyld-private ABI behavior is correct, or that a detector is bypassed.  The
runner reports those production gaps as `known_gaps` instead of disguising
them as host-test coverage.

The callback/catalog fixtures specifically cover replay-before-live ordering,
address reuse after remove, recursive load/unload fail-stop behavior,
allocation-failure fallback, no callback under the registry lock, catalog
snapshot ownership, and the fact that Objective-C load callbacks come only
from the ObjC-runtime relay rather than dyld add-image delivery. They also
characterize the short-lived `RTLD_NOLOAD` pin and post-pin
identity/generation revalidation required before replay can expose a header,
plus TLS virtualization that preserves a callback caller's pending `dlerror`
while consuming a failed `RTLD_NOLOAD` bookkeeping error.

The dyld and ObjC bootstrap relays are permanent multiplexers. A one-way
`FILTERED -> PASSTHROUGH` switch returns public image views to their native
APIs while already-linked registrations receive the exact raw event on the
source relay before it returns; they are never post-hoc registered with dyld
or the ObjC runtime. This avoids a writer-versus-native-relay handoff window.
New registrations after the switch use the originals directly. A registration
which is still replaying when a raw remove arrives is intentionally not called
with a stale header; that ambiguity, or a route flip discovered after partial
filtered delivery, terminally disables hider readiness rather than claiming a
complete callback stream or raw-replaying duplicates. `pthread_atfork` briefly fences catalog/registration
publication in the parent (the only intentional wait) and the child chooses
permanent pass-through, so it never relies on inherited filtering state or a
vanished worker.

Run it from the repository root or from this directory:

```sh
make -C BaseBin/systemhook/tests test
make -C BaseBin/systemhook/tests json > /tmp/rhinject-systemhook-characterization.json
```

`ownership.json` is the machine-readable inventory intended to be handed to
implementation workers.  Every owner path and listed symbol is checked by the
runner so the inventory cannot silently drift.

#!/usr/bin/env python3
"""Host characterization for RootHide randomized-root ownership/recovery.

This intentionally models only the filesystem contract used by DOBootstrapper;
the production Objective-C code runs only with jailbreak privileges on-device.
The source assertions tie the fixtures to the fail-closed implementation.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]
SOURCE = REPO / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
PRIMARY_BASE = Path("/var/containers/Bundle/Application")
SECONDARY_BASE = Path("/var/mobile/Containers/Shared/AppGroup")
CURRENT_ID = "com.m1337v.Opamine"
LEGACY_ID = "com.opa334.Dopamine-roothide"


def branded_name(seed: int) -> str:
    value = seed & ~0xFF
    checksum = 0
    for shift in range(8, 64, 8):
        checksum ^= (value >> shift) & 0xFF
    return f".jbroot-{value | checksum:016X}"


def is_branded(name: str) -> bool:
    if not name.startswith(".jbroot-") or len(name) != len(".jbroot-") + 16:
        return False
    try:
        value = int(name[8:], 16)
    except ValueError:
        return False
    checksum = 0
    for shift in range(8, 64, 8):
        checksum ^= (value >> shift) & 0xFF
    return checksum == (value & 0xFF)


def readlink_state(path: Path, expected: str) -> str:
    if not os.path.lexists(path):
        return "missing"
    if not path.is_symlink():
        return "unexpected"
    return "expected" if os.readlink(path) == expected else "unexpected"


def model_state(primary: Path, secondary_base: Path, current_id: str = CURRENT_ID) -> str:
    marker = primary / ".installed_dopamine"
    if (primary / ".bootstrapped").exists() or (primary / ".thebootstrapped").exists():
        return "foreign"
    if not marker.is_file():
        return "unowned"

    identity = primary / "basebin/.AppIdentifier"
    if os.path.lexists(identity):
        if not identity.is_file():
            return "invalid"
        if identity.read_text().strip() not in {current_id, LEGACY_ID}:
            return "foreign"

    secondary = secondary_base / primary.name
    secondary_var = secondary / "var"
    if not primary.is_dir() or not secondary.is_dir() or not secondary_var.is_dir():
        return "invalid"

    link_states = (
        readlink_state(primary / "var", "private/var"),
        readlink_state(primary / "private/var", str(secondary_var)),
        readlink_state(secondary / ".jbroot", str(primary)),
    )
    if "unexpected" in link_states:
        return "invalid"
    if "missing" in link_states:
        return "repairable"
    return "ready"


def model_discover(primary_base: Path, secondary_base: Path, allow_repairable: bool) -> tuple[str | None, str | None]:
    selected = None
    for candidate in primary_base.iterdir():
        if not is_branded(candidate.name):
            continue
        state = model_state(candidate, secondary_base)
        if state == "unowned":
            continue
        if state in {"foreign", "invalid"} or (state == "repairable" and not allow_repairable):
            return None, state
        if selected is not None:
            return None, "ambiguous"
        selected = candidate
    return selected, None


def model_repair(primary: Path, secondary_base: Path) -> bool:
    if model_state(primary, secondary_base) != "repairable":
        return False
    secondary = secondary_base / primary.name
    for path, target in (
        (primary / "var", "private/var"),
        (primary / "private/var", str(secondary / "var")),
        (secondary / ".jbroot", str(primary)),
    ):
        state = readlink_state(path, target)
        if state == "unexpected":
            return False
        if state == "missing":
            path.symlink_to(target)
    return model_state(primary, secondary_base) == "ready"


def replace_link_atomically(path: Path, target: str) -> None:
    temporary = path.with_name(f"{path.name}.txn")
    temporary.symlink_to(target)
    os.replace(temporary, path)


def model_rerandomize(primary: Path, secondary_base: Path, new_name: str, fail_stage: str | None = None) -> bool:
    """Model the paired move and rollback contract, with deterministic faults."""
    old_primary = primary
    old_secondary = secondary_base / primary.name
    new_primary = primary.with_name(new_name)
    new_secondary = secondary_base / new_name
    moved_primary = moved_secondary = rewrote_private = rewrote_secondary = False

    old_primary.rename(new_primary)
    moved_primary = True
    if fail_stage == "second-move":
        new_primary.rename(old_primary)
        return False
    old_secondary.rename(new_secondary)
    moved_secondary = True
    replace_link_atomically(new_primary / "private/var", str(new_secondary / "var"))
    rewrote_private = True
    replace_link_atomically(new_secondary / ".jbroot", str(new_primary))
    rewrote_secondary = True

    if fail_stage != "validation":
        return True

    # Reverse links before moving either root back, preserving a complete old
    # pair after the injected final-validation failure.
    if rewrote_secondary:
        replace_link_atomically(new_secondary / ".jbroot", str(old_primary))
    if rewrote_private:
        replace_link_atomically(new_primary / "private/var", str(old_secondary / "var"))
    if moved_secondary:
        new_secondary.rename(old_secondary)
    if moved_primary:
        new_primary.rename(old_primary)
    return False


def create_owned_pair(primary_base: Path, secondary_base: Path, seed: int, identity: str | None = CURRENT_ID) -> tuple[Path, Path]:
    name = branded_name(seed)
    primary = primary_base / name
    secondary = secondary_base / name
    (primary / "private").mkdir(parents=True)
    (secondary / "var").mkdir(parents=True)
    (primary / ".installed_dopamine").write_text("2")
    if identity is not None:
        (primary / "basebin").mkdir()
        (primary / "basebin/.AppIdentifier").write_text(identity)
    (primary / "var").symlink_to("private/var")
    (primary / "private/var").symlink_to(secondary / "var")
    (secondary / ".jbroot").symlink_to(primary)
    return primary, secondary


class IdentityRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.primary_base = self.root / PRIMARY_BASE.relative_to("/")
        self.secondary_base = self.root / SECONDARY_BASE.relative_to("/")
        self.primary_base.mkdir(parents=True)
        self.secondary_base.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_jbrand_checksum_and_both_randomized_roots(self) -> None:
        primary, secondary = create_owned_pair(self.primary_base, self.secondary_base, 0x123456789ABCDE00)
        self.assertTrue(is_branded(primary.name))
        self.assertEqual(secondary.name, primary.name)
        selected, error = model_discover(self.primary_base, self.secondary_base, allow_repairable=False)
        self.assertEqual(selected, primary)
        self.assertIsNone(error)

    def test_missing_or_broken_expected_symlinks_are_repaired_only_for_owned_pair(self) -> None:
        primary, secondary = create_owned_pair(self.primary_base, self.secondary_base, 0xA1B2C3D4E5F60700)
        (primary / "private/var").unlink()
        (secondary / ".jbroot").unlink()
        self.assertEqual(model_state(primary, self.secondary_base), "repairable")
        selected, error = model_discover(self.primary_base, self.secondary_base, allow_repairable=True)
        self.assertEqual(selected, primary)
        self.assertIsNone(error)
        self.assertTrue(model_repair(primary, self.secondary_base))
        self.assertEqual(model_state(primary, self.secondary_base), "ready")

    def test_wrong_symlink_target_fails_closed_without_replacement(self) -> None:
        primary, _ = create_owned_pair(self.primary_base, self.secondary_base, 0x1020304050607000)
        (primary / "private/var").unlink()
        (primary / "private/var").symlink_to("/unrelated/var")
        self.assertEqual(model_state(primary, self.secondary_base), "invalid")
        self.assertFalse(model_repair(primary, self.secondary_base))
        self.assertEqual(os.readlink(primary / "private/var"), "/unrelated/var")

    def test_dangling_expected_symlink_fails_closed_when_its_paired_data_is_missing(self) -> None:
        primary, secondary = create_owned_pair(self.primary_base, self.secondary_base, 0x9988776655443300)
        shutil.rmtree(secondary / "var")
        self.assertEqual(model_state(primary, self.secondary_base), "invalid")
        selected, error = model_discover(self.primary_base, self.secondary_base, allow_repairable=True)
        self.assertIsNone(selected)
        self.assertEqual(error, "invalid")
        self.assertEqual(os.readlink(primary / "private/var"), str(secondary / "var"))

    def test_failed_second_paired_move_rolls_back_the_first_move(self) -> None:
        primary, secondary = create_owned_pair(self.primary_base, self.secondary_base, 0x0102030405060700)
        new_name = branded_name(0x1112131415161700)
        self.assertFalse(model_rerandomize(primary, self.secondary_base, new_name, fail_stage="second-move"))
        self.assertTrue(primary.exists())
        self.assertTrue(secondary.exists())
        self.assertEqual(model_state(primary, self.secondary_base), "ready")
        self.assertFalse((self.primary_base / new_name).exists())

    def test_failed_final_validation_restores_the_original_complete_pair(self) -> None:
        primary, secondary = create_owned_pair(self.primary_base, self.secondary_base, 0x2122232425262700)
        new_name = branded_name(0x3132333435363700)
        self.assertFalse(model_rerandomize(primary, self.secondary_base, new_name, fail_stage="validation"))
        self.assertTrue(primary.exists())
        self.assertTrue(secondary.exists())
        self.assertEqual(model_state(primary, self.secondary_base), "ready")
        self.assertFalse((self.primary_base / new_name).exists())

    def test_cache_is_not_seeded_until_bootstrap_extraction_succeeds(self) -> None:
        source = SOURCE.read_text()
        extraction = source.index("extractTar:bootstrapTarFile toPath:jbroot_path")
        success_cache = source.index("RootHideSetCachedJailbreakRoot(jbroot_path);", extraction)
        failure_clear = source.index("RootHideSetCachedJailbreakRoot(nil);", extraction)
        self.assertLess(failure_clear, success_cache)

    def test_multiple_owned_candidates_are_ambiguous(self) -> None:
        first, _ = create_owned_pair(self.primary_base, self.secondary_base, 0x1111111111111100)
        second, _ = create_owned_pair(self.primary_base, self.secondary_base, 0x2222222222222200)
        selected, error = model_discover(self.primary_base, self.secondary_base, allow_repairable=True)
        self.assertIsNone(selected)
        self.assertEqual(error, "ambiguous")
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_prior_roothide_identity_is_adopted_but_unknown_identity_is_not(self) -> None:
        primary, _ = create_owned_pair(self.primary_base, self.secondary_base, 0x3333333333333300, identity=LEGACY_ID)
        self.assertEqual(model_state(primary, self.secondary_base, current_id="com.m1337v.Opamine"), "ready")
        identity = primary / "basebin/.AppIdentifier"
        identity.write_text("com.someone.else.root")
        self.assertEqual(model_state(primary, self.secondary_base), "foreign")
        selected, error = model_discover(self.primary_base, self.secondary_base, allow_repairable=True)
        self.assertIsNone(selected)
        self.assertEqual(error, "foreign")
        self.assertEqual(identity.read_text(), "com.someone.else.root")

    def test_unrelated_preboot_entries_are_not_discovered_or_removed(self) -> None:
        primary, _ = create_owned_pair(self.primary_base, self.secondary_base, 0x4444444444444400)
        preboot = self.root / "private/preboot/current-manifest"
        unrelated = preboot / "orphaned-unrelated"
        unrelated.mkdir(parents=True)
        (unrelated / "sentinel").write_text("do not touch")
        selected, error = model_discover(self.primary_base, self.secondary_base, allow_repairable=False)
        self.assertEqual(selected, primary)
        self.assertIsNone(error)
        self.assertTrue((unrelated / "sentinel").exists())

    def test_source_contains_fail_closed_contract(self) -> None:
        source = SOURCE.read_text()
        for anchor in (
            "RootHideJailbreakRootStateForPrimaryPath",
            "RootHideRepairPairedRootLinks",
            "RootHideDiscoverAndRecoverOwnedJailbreakRoot",
            "RootHideReplaceExpectedSymlink",
            "RootHideFindOwnedJailbreakRoot",
            "RootHideWriteCurrentAppIdentifier",
            "Multiple owned RootHide/Opamine randomized roots",
            "Never remove a directory just because it has a valid randomized-root",
            "goto rollback",
            "activePrebootPath",
        ):
            self.assertIn(anchor, source)
        self.assertNotIn('STRAPLOG("remove unknown/unfinished jbroot', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

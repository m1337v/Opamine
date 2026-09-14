#!/bin/sh

# Read-only verifier for the RootHide Opamine/Dopamine 3 migration.
# The baseline is an immutable ancestor recorded in the WP0 manifest; the
# script never checks out, updates submodules, unpacks into the repository,
# rewrites packages/plists, or mutates production sources.

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
failures=0

pass() { printf 'PASS %s\n' "$1"; }
note() { printf 'NOTE %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1" >&2; failures=$((failures + 1)); }

require_tool() {
	if ! command -v "$1" >/dev/null 2>&1; then fail "required tool is unavailable: $1"; fi
}

source_contains() {
	path=$1
	needle=$2
	if [ ! -f "$repo_root/$path" ]; then fail "missing source anchor: $path"; return; fi
	if grep -Fq "$needle" "$repo_root/$path"; then
		pass "$path contains $needle"
	else
		fail "$path does not contain expected anchor: $needle"
	fi
}

baseline_source_contains() {
	path=$1
	needle=$2
	source=$(git -C "$repo_root" show "$baseline_commit:$path" 2>/dev/null || true)
	if [ -z "$source" ]; then fail "missing baseline source anchor: $path"; return; fi
	if case "$source" in *"$needle"*) true ;; *) false ;; esac; then
		pass "$baseline_commit:$path contains $needle"
	else
		fail "$baseline_commit:$path does not contain expected anchor: $needle"
	fi
}

check_submodule() {
	path=$1
	expected=$2
	actual=$(git -C "$repo_root/$path" rev-parse HEAD 2>/dev/null || true)
	if [ "$actual" = "$expected" ]; then
		pass "submodule $path at $actual"
	else
		fail "submodule $path expected $expected, got ${actual:-missing}"
	fi
}

check_control_version() {
	path=$1
	package=$2
	version=$3
	if [ ! -f "$repo_root/$path" ]; then fail "missing package control: $path"; return; fi
	actual_package=$(awk -F': ' '$1 == "Package" { print $2; exit }' "$repo_root/$path")
	actual_version=$(awk -F': ' '$1 == "Version" { print $2; exit }' "$repo_root/$path")
	if [ "$actual_package" = "$package" ] && [ "$actual_version" = "$version" ]; then
		pass "package control $package $version"
	else
		fail "$path expected $package $version, got ${actual_package:-missing} ${actual_version:-missing}"
	fi
}

check_deb() {
	path=$1
	package=$2
	version=$3
	architecture=$4
	expected_sha256=$5
	if [ ! -f "$repo_root/$path" ]; then fail "missing package artifact: $path"; return; fi
	actual_package=$(dpkg-deb -f "$repo_root/$path" Package 2>/dev/null || true)
	actual_version=$(dpkg-deb -f "$repo_root/$path" Version 2>/dev/null || true)
	actual_architecture=$(dpkg-deb -f "$repo_root/$path" Architecture 2>/dev/null || true)
	actual_sha256=$(shasum -a 256 "$repo_root/$path" | awk '{ print $1 }')
	if [ "$actual_package" != "$package" ] || [ "$actual_version" != "$version" ] || [ "$actual_architecture" != "$architecture" ]; then
		fail "$path metadata mismatch: expected $package $version $architecture, got ${actual_package:-missing} ${actual_version:-missing} ${actual_architecture:-missing}"
	elif [ "$expected_sha256" = "-" ]; then
		pass "package $package $version ($architecture) metadata; rebuilt archive hash $actual_sha256"
	elif [ "$actual_sha256" != "$expected_sha256" ]; then
		fail "$path SHA-256 mismatch: expected $expected_sha256, got $actual_sha256"
	else
		pass "package $package $version ($architecture) and SHA-256"
	fi
}

for tool in git awk grep shasum stat od plutil xcodebuild xcrun dpkg-deb tar make; do require_tool "$tool"; done

baseline_commit=${BASELINE_COMMIT:-1b40dbdb17ff60e106d91ce87c0da249923aa31f}
actual_head=$(git -C "$repo_root" rev-parse HEAD)
if git -C "$repo_root" cat-file -e "$baseline_commit^{commit}" 2>/dev/null &&
	git -C "$repo_root" merge-base --is-ancestor "$baseline_commit" "$actual_head"; then
	pass "repository contains immutable baseline $baseline_commit (HEAD $actual_head)"
else
	fail "repository HEAD $actual_head does not descend from baseline $baseline_commit"
fi
actual_branch=$(git -C "$repo_root" branch --show-current)
if [ "$actual_branch" = "rhinject" ]; then pass "repository branch rhinject"; else fail "repository branch expected rhinject, got ${actual_branch:-detached}"; fi

check_submodule BaseBin/ChOma 7dccded6bc17081c08f5f5cdbd7a4b051543a825
check_submodule BaseBin/XPF 1e5da55fc6d8221e90b18659d44564acb12f903c
check_submodule BaseBin/XPF/external/ChOma 7dccded6bc17081c08f5f5cdbd7a4b051543a825
check_submodule BaseBin/_external/modules/litehook 0d9d17afc011d2a8dfe67a4f7803ff99143d0f0d
check_submodule BaseBin/opainject 849bb296ea8bc0643a2966485ea3c3c96ebdcd5b

kfd_path=Application/Dopamine/Dopamine/Exploits/kfd/kfd
if git -C "$repo_root" cat-file -e "HEAD:$kfd_path" 2>/dev/null; then
	fail "unexpected kfd gitlink at HEAD:$kfd_path"
else
	pass "kfd declaration has no target-HEAD gitlink (expected baseline state)"
fi

xcode_version=$(xcodebuild -version 2>/dev/null || true)
if printf '%s\n' "$xcode_version" | grep -Fq 'Xcode 16.4' && printf '%s\n' "$xcode_version" | grep -Fq 'Build version 16F6'; then pass "Xcode 16.4 (16F6)"; else fail "Xcode expected 16.4 (16F6), got ${xcode_version:-unavailable}"; fi
iphoneos_sdk=$(xcrun --sdk iphoneos --show-sdk-version 2>/dev/null || true)
if [ "$iphoneos_sdk" = "18.5" ]; then pass "iPhoneOS SDK 18.5"; else fail "iPhoneOS SDK expected 18.5, got ${iphoneos_sdk:-unavailable}"; fi
clang_version=$(clang --version 2>/dev/null | sed -n '1p' || true)
if printf '%s\n' "$clang_version" | grep -Fq 'Apple clang version 17.0.0'; then pass "Apple clang 17.0.0"; else fail "Apple clang expected 17.0.0, got ${clang_version:-unavailable}"; fi
swift_version=$(swiftc --version 2>/dev/null | sed -n '1p' || true)
if printf '%s\n' "$swift_version" | grep -Fq 'Apple Swift version 6.1.2'; then pass "Apple Swift 6.1.2"; else fail "Apple Swift expected 6.1.2, got ${swift_version:-unavailable}"; fi
if printf '%s\n' "$(ldid -V 2>&1 || true)" | grep -Fq '2.1.5-procursus7'; then pass "Procursus ldid 2.1.5-procursus7"; else fail "Procursus ldid expected 2.1.5-procursus7"; fi

baseline_basebin_version=$(git -C "$repo_root" show "$baseline_commit:BaseBin/_external/basebin/.version" 2>/dev/null | tr -d '\r\n' || true)
if [ "$baseline_basebin_version" = "2.4.9.28" ]; then
	pass "$baseline_commit basebin version 2.4.9.28"
else
	fail "$baseline_commit basebin version expected 2.4.9.28, got ${baseline_basebin_version:-missing}"
fi

version_is_after()
{
	awk -F. -v left="$1" -v right="$2" '
		BEGIN {
			n = split(left, l); m = split(right, r);
			for (i = 1; i <= (n > m ? n : m); i++) {
				lv = (i <= n ? l[i] + 0 : 0);
				rv = (i <= m ? r[i] + 0 : 0);
				if (lv > rv) exit 0;
				if (lv < rv) exit 1;
			}
			exit 1;
		}'
}

current_basebin_version=$(tr -d '\r\n' < "$repo_root/BaseBin/_external/basebin/.version" 2>/dev/null || true)
planned_release_version=${EXPECTED_BASEBIN_VERSION:-3.0.9.1}
if version_is_after "$current_basebin_version" 3.0.9; then
	pass "current basebin version $current_basebin_version is above official 3.0.9"
	if [ "$current_basebin_version" = "$planned_release_version" ]; then
		pass "planned Opamine release version $planned_release_version"
	else
		note "current basebin version is $current_basebin_version; planned release target is $planned_release_version"
	fi
else
	note "release gate pending: basebin version ${current_basebin_version:-missing} must be above official 3.0.9 (target $planned_release_version) before packaging"
	if [ "${REQUIRE_RELEASE_VERSION:-0}" = 1 ]; then
		fail "release version gate requires $planned_release_version or a later version"
	fi
fi

check_deb Application/Dopamine/Resources/sileo.deb org.coolstar.sileo '2.5.1-13+opamine1' iphoneos-arm64e a26532c514eec10f4cf002d602c7ddc9b2c7ca9ab14963d0296e5c6f89f85db6
check_deb Application/Dopamine/Resources/roothide.deb roothide '0.1.0-0+opamine1' iphoneos-arm64e 6c2c521d33a668829e719f489676817b74d0c19e5f79065f6c9cf81b623810c1
check_deb Application/Dopamine/Resources/roothideapp.deb com.roothide.manager '1.3.9' iphoneos-arm64e b8f075e1844709845962900b22fe71136a66369a2c35bb1201087f2fd9476b7d
check_deb Application/Dopamine/Resources/zebra.deb xyz.willy.zebra '1.1.36-2-1+debug' iphoneos-arm64e ca82c18256e19ff78af3e53308d53f047a2d429cb7e025c892377abe4d2e7825
# These three packages are rebuilt locally by the ordinary full build. Their
# Debian ar/tar timestamps make whole-archive hashes intentionally unstable;
# validate package identity here and their source controls below. Embedded
# third-party/fork packages remain pinned by exact SHA-256 above.
check_deb Packages/basebin-link/basebin-link.deb dopamine-basebin-link 1.0.0 iphoneos-arm64e -
check_deb Packages/libkrw-provider/libkrw-dopamine.deb libkrw0-dopamine 2.0.4 iphoneos-arm64e -
check_deb Packages/libroot/libroot.deb libroot-dopamine 1.0.1 iphoneos-arm64 -

check_control_version Packages/basebin-link/control dopamine-basebin-link 1.0.0
check_control_version Packages/libkrw-provider/control libkrw0-dopamine 2.0.4
check_control_version Packages/libroot/control libroot-dopamine 1.0.1
check_control_version BaseBin/opainject/control com.opa334.opainject 1.0.6
check_control_version BaseBin/roothidehooks/control com.roothide.dopamine.roothidehooks 0.0.1
source_contains Scripts/build-fork-packages.sh 'sileo_fork_version="2.5.1-13+opamine1"'
source_contains Scripts/build-fork-packages.sh 'roothide_fork_version="0.1.0-0+opamine1"'
source_contains Scripts/build-fork-packages.sh 'sileo_sha256="b23e51371938bb6257ba82abdcdae9a6519755556b874b06672868c64843a0f6"'
source_contains Scripts/build-fork-packages.sh 'roothide_sha256="06adc371ec37e7356762c875ca682bfb2f9b33a1100fb14168653b7e571ca670"'

sileo_info=$(dpkg-deb --fsys-tarfile "$repo_root/Application/Dopamine/Resources/sileo.deb" | tar -xOf - ./Applications/Sileo.app/Info.plist | plutil -p -)
if printf '%s\n' "$sileo_info" | grep -Eq 'CFBundleURLTypes|CFBundleURLSchemes'; then fail "Sileo package still declares URL-registration keys"; else pass "Sileo package Info.plist has no URL-registration keys"; fi
if printf '%s\n' "$sileo_info" | grep -Fq 'LSApplicationQueriesSchemes' && printf '%s\n' "$sileo_info" | grep -Fq 'filza'; then pass "Sileo retains only the observed filza query scheme"; else fail "Sileo query-scheme characterization changed"; fi

source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m '#define JB_ROOT_PREFIX ".jbroot-"'
source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m '#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)'
source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m 'return (value & ~0xFF) | check;'
source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m 'is_jbrand_value(value)'
if grep -Fq '/var/containers/Bundle/Application' "$repo_root/Application/Dopamine/Jailbreak/DOBootstrapper.m" &&
	grep -Fq '".jbroot-%016llX"' "$repo_root/Application/Dopamine/Jailbreak/DOBootstrapper.m"; then
	pass "Application/Dopamine/Jailbreak/DOBootstrapper.m retains randomized primary-root construction"
else
	fail "Application/Dopamine/Jailbreak/DOBootstrapper.m randomized primary-root construction is missing"
fi
source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m '/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX'
source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m 'createSymbolicLinkAtPath:[jbroot_secondary stringByAppendingPathComponent:@".jbroot"]'
source_contains Application/Dopamine/Jailbreak/DOBootstrapper.m 'return [@"/rootfs/" stringByAppendingPathComponent:path];'

source_contains BaseBin/libjailbreak/src/roothider/common.m 'int randomizeAndLoadBasebinTrustcache(const char* basebinPath)'
source_contains BaseBin/libjailbreak/src/roothider/common.m 'ensure_randomized_cdhash(fileURL.path.fileSystemRepresentation, cdhash)'
source_contains BaseBin/libjailbreak/src/roothider/common.m 'trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID)'
source_contains Application/Dopamine/Jailbreak/DOJailbreaker.m 'randomizeAndLoadBasebinTrustcache(JBROOT_PATH("/basebin/"))'
if grep -Fq 'if (tcSize > 0x4000) return -1;' "$repo_root/BaseBin/libjailbreak/src/trustcache.c" ||
	(grep -Fq 'if (size > JB_TRUSTCACHE_SIZE) return -E2BIG;' "$repo_root/BaseBin/libjailbreak/src/trustcache.c" &&
	 grep -Fq '#define JB_TRUSTCACHE_SIZE 0x4000' "$repo_root/BaseBin/libjailbreak/src/trustcache_structs.h"); then
	pass "BaseBin/libjailbreak trustcache allocation remains bounded to 0x4000"
else
	fail "BaseBin/libjailbreak trustcache allocation bound is missing or unrecognised"
fi
source_contains BaseBin/libjailbreak/src/trustcache.c 'trustcache_file_upload_with_uuid(trustcache_file_v1 *tc, uuid_t uuid)'
baseline_source_contains BaseBin/libjailbreak/src/trustcache.c 'if (prevTcSize == tcSize)'

# WP1 may already have changed the worktree same-size write.  Accept either
# known state, but reject drift into an unbounded or unrecognised write form.
if grep -Fq 'size_t payloadSize = (size_t)(tcSize - ksizeof(trustcache));' "$repo_root/BaseBin/libjailbreak/src/trustcache.c" &&
	grep -Fq 'kwritebuf(existingTcFile, tc, payloadSize)' "$repo_root/BaseBin/libjailbreak/src/trustcache.c" &&
	grep -Fq 'kwritebuf(existingTcFile, previousPayload, payloadSize)' "$repo_root/BaseBin/libjailbreak/src/trustcache.c"; then
	pass "same-size trustcache replacement and rollback are payload-bounded"
elif grep -Fq 'kwritebuf(prevTcFile, tc, tcSize - ksizeof(trustcache))' "$repo_root/BaseBin/libjailbreak/src/trustcache.c" ||
	grep -Fq 'kwritebuf(existingTcFile, tc, tcSize - ksizeof(trustcache))' "$repo_root/BaseBin/libjailbreak/src/trustcache.c"; then
	pass "same-size trustcache replacement is payload-bounded"
elif grep -Fq 'kwritebuf(prevTcFile, tc, tcSize)' "$repo_root/BaseBin/libjailbreak/src/trustcache.c"; then
	note "same-size trustcache replacement is historical HEAD form; WP1 remains pending"
else
	fail "same-size trustcache replacement write is missing or unrecognised"
fi

trustcache_path="$repo_root/BaseBin/basebin.tc"
if [ -f "$trustcache_path" ]; then
	tc_version=$(od -An -tu4 -j 0 -N 4 "$trustcache_path" | tr -d ' ')
	tc_entries=$(od -An -tu4 -j 20 -N 4 "$trustcache_path" | tr -d ' ')
	tc_size=$(stat -f '%z' "$trustcache_path")
	tc_expected_size=$((24 + tc_entries * 22))
	if [ "$tc_version" = 1 ] && [ "$tc_entries" = 29 ] && [ "$tc_size" = 662 ] && [ "$tc_size" = "$tc_expected_size" ]; then
		pass "BaseBin/basebin.tc structure (version 1, 29 entries, 662 bytes)"
	else
		fail "BaseBin/basebin.tc structure mismatch: version=$tc_version entries=$tc_entries size=$tc_size expected=$tc_expected_size"
	fi
	if [ -f "$repo_root/BaseBin/.build/basebin.tc" ] && cmp -s "$trustcache_path" "$repo_root/BaseBin/.build/basebin.tc"; then
		pass "BaseBin/basebin.tc matches .build/basebin.tc"
	else
		note "BaseBin/.build/basebin.tc is absent or differs"
	fi
else
	note "BaseBin/basebin.tc is absent; run trustcache generation before artifact verification"
fi

for mode in stock blacklist whitelist hiddenwhitelist blacklistallowlist; do
	source_contains BaseBin/libjailbreak/src/roothider/blacklist.m "@\"$mode\""
done
source_contains BaseBin/libjailbreak/src/roothider/blacklist.m 'kRootHideModeRelativePath'
source_contains BaseBin/systemhook/src/common.c 'bool root_hide_injection_mode_is_hidden_whitelist(void)'
source_contains BaseBin/systemhook/src/common.c 'bool root_hide_injection_mode_is_blacklist_allowlist(void)'
source_contains BaseBin/systemhook/src/common.c 'bool root_hide_injection_mode_uses_whitelist_rules(void)'
source_contains BaseBin/systemhook/src/roothider_main.c 'bool roothide_hidden_tweak_load_selected(void)'
source_contains BaseBin/systemhook/src/hider_caller_policy.c 'bool rhi_hider_caller_can_read_hidden(const void *return_address)'
source_contains BaseBin/systemhook/tests/ownership.json '"modes"'
source_contains BaseBin/systemhook/tests/ownership.json '"blacklistallowlist"'

for path in \
	BaseBin/libjailbreak/src/roothider \
	BaseBin/roothidehooks \
	BaseBin/launchdhook/src/roothider.m \
	BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c \
	BaseBin/systemhook/src/hider_caller_policy.c \
	BaseBin/systemhook/src/hider_environment_policy.c \
	BaseBin/systemhook/src/hider_hook_session.c \
	BaseBin/systemhook/src/hider_identity.c \
	BaseBin/systemhook/src/hider_path_policy.c \
	BaseBin/systemhook/src/rhi_rebind.c \
	Application/Dopamine/Jailbreak/DOBootstrapper.m \
	Application/Dopamine/Jailbreak/DOJailbreaker.m \
	Application/Dopamine/Dopamine.entitlements \
	Scripts/build-fork-packages.sh; do
	if [ ! -e "$repo_root/$path" ]; then
		fail "owned-path manifest anchor is missing: $path"
	fi
done
pass "RootHide/Opamine owned-path anchor set is present"

if [ -n "$(git -C "$repo_root" status --short --untracked-files=all)" ]; then
	note "worktree has unrelated/in-progress edits; use STRICT_CLEAN=1 to make this a failure"
	if [ "${STRICT_CLEAN:-0}" = 1 ]; then fail "worktree is not clean"; fi
else
	pass "worktree clean"
fi

if [ "${RUN_HOST_TESTS:-1}" = 1 ]; then
	if make -C "$repo_root/BaseBin/systemhook/tests" test; then
		pass "systemhook host characterization lane"
	else
		fail "systemhook host characterization lane"
	fi
else
	note "systemhook host characterization skipped (RUN_HOST_TESTS=0)"
fi

if [ -f "$repo_root/BaseBin/libjailbreak/tests/Makefile" ] && [ "${RUN_TRUSTCACHE_TESTS:-1}" = 1 ]; then
	if make -C "$repo_root/BaseBin/libjailbreak/tests" test; then
		pass "trustcache host characterization lane"
	else
		fail "trustcache host characterization lane"
	fi
elif [ "${RUN_TRUSTCACHE_TESTS:-1}" = 1 ]; then
	note "trustcache characterization lane is not present in this checkout"
else
	note "trustcache host characterization skipped (RUN_TRUSTCACHE_TESTS=0)"
fi

if [ "$failures" -eq 0 ]; then
	printf 'BASELINE PASS\n'
	exit 0
fi

printf 'BASELINE FAIL (%d failures)\n' "$failures" >&2
exit 1

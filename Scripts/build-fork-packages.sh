#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
resource_dir="$repo_root/Application/Dopamine/Resources"
work_dir=$(mktemp -d /tmp/opamine-fork-packages.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
export SOURCE_DATE_EPOCH=1775088000

sileo_url="https://roothide.github.io/debfiles/org.coolstar.sileo_2.5.1-13_iphoneos-arm64e.deb"
sileo_sha256="b23e51371938bb6257ba82abdcdae9a6519755556b874b06672868c64843a0f6"
sileo_source_version="2.5.1-13"
sileo_fork_version="2.5.1-13+opamine1"

roothide_url="https://roothide.github.io/procursus/pool/main/iphoneos-arm64e/1900/roothide/roothide_0.1.0_iphoneos-arm64e.deb"
roothide_sha256="06adc371ec37e7356762c875ca682bfb2f9b33a1100fb14168653b7e571ca670"
roothide_source_version="0.1.0"
roothide_fork_version="0.1.0-0+opamine1"

require_tool()
{
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required tool: $1" >&2
		exit 1
	}
}

sha256_file()
{
	shasum -a 256 "$1" | awk '{print $1}'
}

sha1_file()
{
	shasum -a 1 "$1" | awk '{print $1}'
}

normalize_ar_headers()
{
	archive=$1
	AR_ARCHIVE="$archive" AR_EPOCH="$SOURCE_DATE_EPOCH" perl -e '
		use strict;
		use warnings;
		my $path = $ENV{"AR_ARCHIVE"};
		my $epoch = 0 + $ENV{"AR_EPOCH"};
		open my $fh, "+<", $path or die "open $path: $!\n";
		binmode $fh;
		local $/;
		my $blob = <$fh>;
		die "invalid ar archive\n" unless substr($blob, 0, 8) eq "!<arch>\n";
		my $offset = 8;
		while ($offset < length($blob)) {
			die "truncated ar header\n" if $offset + 60 > length($blob);
			my $size = 0 + substr($blob, $offset + 48, 10);
			substr($blob, $offset + 16, 12) = sprintf("%-12d", $epoch);
			substr($blob, $offset + 28, 6) = sprintf("%-6d", 0);
			substr($blob, $offset + 34, 6) = sprintf("%-6d", 0);
			$offset += 60 + $size + ($size % 2);
		}
		die "invalid ar member size\n" unless $offset == length($blob);
		seek $fh, 0, 0 or die "seek $path: $!\n";
		print {$fh} $blob or die "write $path: $!\n";
		truncate $fh, length($blob) or die "truncate $path: $!\n";
		close $fh or die "close $path: $!\n";
	'
}

payload_manifest()
{
	root=$1
	(
		cd "$root"
		find . -mindepth 1 -print | LC_ALL=C sort | while IFS= read -r path; do
			if [ -L "$path" ]; then
				printf 'link  %s %s -> %s\n' "$(stat -f '%Lp' "$path")" "$path" "$(readlink "$path")"
			elif [ -f "$path" ]; then
				printf 'file  %s %s %s\n' "$(stat -f '%Lp' "$path")" "$path" "$(sha256_file "$path")"
			elif [ -d "$path" ]; then
				printf 'dir   %s %s\n' "$(stat -f '%Lp' "$path")" "$path"
			else
				printf 'other %s\n' "$path"
			fi
		done
	)
}

require_package()
{
	deb=$1
	expected_package=$2
	expected_version=$3

	actual_package=$(dpkg-deb -f "$deb" Package)
	actual_version=$(dpkg-deb -f "$deb" Version)
	[ "$actual_package" = "$expected_package" ] || {
		echo "unexpected package id: $actual_package" >&2
		exit 1
	}
	[ "$actual_version" = "$expected_version" ] || {
		echo "unexpected $actual_package version: $actual_version" >&2
		exit 1
	}
}

set_package_version()
{
	control=$1
	old_version=$2
	new_version=$3

	OLD_VERSION="$old_version" NEW_VERSION="$new_version" perl -0pi -e '
		BEGIN { $old = $ENV{"OLD_VERSION"}; $new = $ENV{"NEW_VERSION"}; }
		$changed += s/^Version: \Q$old\E$/Version: $new/m;
		END { die "version field not replaced\n" unless $changed == 1; }
	' "$control"
}

require_tool curl
require_tool dpkg-deb
require_tool ar
require_tool gtar
require_tool ldid
require_tool perl
require_tool plutil
require_tool shasum
require_tool zstd

sileo_input="$work_dir/sileo-source.deb"
roothide_input="$work_dir/roothide-source.deb"

curl -fsSL "$sileo_url" -o "$sileo_input"
curl -fsSL "$roothide_url" -o "$roothide_input"

[ "$(sha256_file "$sileo_input")" = "$sileo_sha256" ] || {
	echo "Sileo source checksum mismatch" >&2
	exit 1
}
[ "$(sha256_file "$roothide_input")" = "$roothide_sha256" ] || {
	echo "RootHide Core source checksum mismatch" >&2
	exit 1
}

require_package "$sileo_input" org.coolstar.sileo "$sileo_source_version"
require_package "$roothide_input" roothide "$roothide_source_version"

sileo_tree="$work_dir/sileo-tree"
dpkg-deb -R "$sileo_input" "$sileo_tree"

sileo_plist="$sileo_tree/Applications/Sileo.app/Info.plist"
sileo_executable="$sileo_tree/Applications/Sileo.app/Sileo"
sileo_entitlements="$work_dir/sileo-entitlements.xml"
[ -f "$sileo_plist" ] || {
	echo "Sileo Info.plist not found" >&2
	exit 1
}
ldid -e "$sileo_executable" > "$sileo_entitlements"
/usr/libexec/PlistBuddy -c 'Delete :CFBundleURLTypes' "$sileo_plist"
if plutil -p "$sileo_plist" | grep -Eq 'CFBundleURLTypes|CFBundleURLSchemes'; then
	echo "Sileo URL scheme registration remains" >&2
	exit 1
fi
ldid -w -S"$sileo_entitlements" "$sileo_tree/Applications/Sileo.app"
sileo_resigned_entitlements="$work_dir/sileo-resigned-entitlements.xml"
ldid -e "$sileo_executable" > "$sileo_resigned_entitlements"
cmp -s "$sileo_entitlements" "$sileo_resigned_entitlements" || {
	echo "Sileo entitlements changed while resigning" >&2
	exit 1
}
sileo_info_sha1=$(sha1_file "$sileo_plist")
plutil -p "$sileo_tree/Applications/Sileo.app/_CodeSignature/CodeResources" |
	grep -Fq "\"Info.plist\" => {length = 20, bytes = 0x$sileo_info_sha1}" || {
	echo "Sileo resource seal does not match the modified Info.plist" >&2
	exit 1
}

set_package_version "$sileo_tree/DEBIAN/control" "$sileo_source_version" "$sileo_fork_version"

sileo_output="$work_dir/sileo.deb"
roothide_output="$work_dir/roothide.deb"
dpkg-deb --build --root-owner-group "$sileo_tree" "$sileo_output" >/dev/null

# RootHide Core owns ./var/mobile as 501:501. Rebuilding the data tree with
# --root-owner-group silently changes that ownership, so retain the pinned
# data archive byte-for-byte and replace only the package control archive.
roothide_parts="$work_dir/roothide-parts"
roothide_control="$work_dir/roothide-control"
mkdir "$roothide_parts" "$roothide_control"
(
	cd "$roothide_parts"
	ar -x "$roothide_input"
)
[ -f "$roothide_parts/debian-binary" ] &&
	[ -f "$roothide_parts/control.tar.zst" ] &&
	[ -f "$roothide_parts/data.tar.zst" ] || {
	echo "unexpected RootHide Core archive layout" >&2
	exit 1
}
roothide_data_sha256=$(sha256_file "$roothide_parts/data.tar.zst")
dpkg-deb -e "$roothide_input" "$roothide_control"
set_package_version "$roothide_control/control" "$roothide_source_version" "$roothide_fork_version"
(
	cd "$roothide_control"
	gtar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
		--mtime="@$SOURCE_DATE_EPOCH" -cf - .
) | zstd -q -f -19 -T1 -o "$roothide_parts/control.tar.zst"
(
	cd "$roothide_parts"
	ar -rc "$roothide_output" debian-binary control.tar.zst data.tar.zst
)
normalize_ar_headers "$roothide_output"

require_package "$sileo_output" org.coolstar.sileo "$sileo_fork_version"
require_package "$roothide_output" roothide "$roothide_fork_version"

sileo_check="$work_dir/sileo-check"
sileo_source_check="$work_dir/sileo-source-check"
dpkg-deb -x "$sileo_output" "$sileo_check"
dpkg-deb -x "$sileo_input" "$sileo_source_check"

if plutil -p "$sileo_check/Applications/Sileo.app/Info.plist" | grep -Eq 'CFBundleURLTypes|CFBundleURLSchemes'; then
	echo "built Sileo package exposes a URL scheme" >&2
	exit 1
fi
payload_manifest "$sileo_source_check" > "$work_dir/sileo-source.manifest"
payload_manifest "$sileo_check" > "$work_dir/sileo-output.manifest"
for manifest in "$work_dir/sileo-source.manifest" "$work_dir/sileo-output.manifest"; do
	perl -ni -e 'print unless m{^file  [0-9]+ \./Applications/Sileo\.app/(?:Info\.plist|Sileo|_CodeSignature/CodeResources) }' "$manifest"
done
diff -u "$work_dir/sileo-source.manifest" "$work_dir/sileo-output.manifest" || {
	echo "Sileo payload changed outside Info.plist and its refreshed signature" >&2
	exit 1
}
[ "$roothide_data_sha256" = "$(
	output_parts="$work_dir/roothide-output-parts"
	mkdir "$output_parts"
	cd "$output_parts"
	ar -x "$roothide_output" data.tar.zst
	sha256_file data.tar.zst
)" ] || {
	echo "RootHide Core data archive changed while repackaging" >&2
	exit 1
}

mv "$sileo_output" "$resource_dir/sileo.deb"
mv "$roothide_output" "$resource_dir/roothide.deb"

echo "Sileo: $(dpkg-deb -f "$resource_dir/sileo.deb" Version) $(sha256_file "$resource_dir/sileo.deb")"
echo "RootHide Core: $(dpkg-deb -f "$resource_dir/roothide.deb" Version) $(sha256_file "$resource_dir/roothide.deb")"

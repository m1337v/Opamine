#include "hider_path_policy.h"

#include <stddef.h>
#include <string.h>

/*
 * This is deliberately a lexical policy, not a canonical-path resolver.
 * Callers receive the same decision for the literal path they supplied; no
 * symlink target, mount point, or filesystem state can broaden concealment.
 */

static const char *const k_hidden_loader_basenames[] = {
	"systemhook",
	"systemhook.dylib",
	"TweakLoader",
	"TweakLoader.dylib",
	"ellekit",
	"ellekit.dylib",
	"libellekit",
	"libellekit.dylib",
	"MobileSubstrate",
	"MobileSubstrate.dylib",
	"CydiaSubstrate",
	"CydiaSubstrate.dylib",
	"libsubstrate",
	"libsubstrate.dylib",
	"libsubstitute",
	"libsubstitute.dylib",
	"SubstrateLoader",
	"SubstrateLoader.dylib",
	"substitute-loader",
	"substitute-loader.dylib",
	"TweakInject",
	"TweakInject.dylib",
	"roothideinit",
	"roothideinit.dylib",
	"roothidepatch",
	"roothidepatch.dylib",
	"libroothide",
	"libroothide.dylib",
	"libroot",
	"libroot.dylib",
	"SSLKillSwitch",
	"SSLKillSwitch.dylib",
	"FridaGadget",
	"FridaGadget.dylib",
	"cynject",
	"cynject.dylib",
	NULL,
};

static const char *const k_hidden_filesystem_paths[] = {
	"/Applications/Cydia.app",
	"/Applications/Sileo.app",
	"/Applications/Zebra.app",
	"/Applications/Filza.app",
	"/Applications/Substitute.app",
	"/Applications/checkra1n.app",
	"/Applications/crackerxi.app",
	"/Library/MobileSubstrate",
	"/usr/sbin/frida-server",
	"/usr/lib/libjailbreak.dylib",
	"/usr/lib/libhooker.dylib",
	"/usr/lib/libsubstitute.dylib",
	"/usr/lib/substrate",
	"/usr/lib/TweakInject",
	"/var/lib/dpkg",
	"/var/lib/cydia",
	"/var/log/syslog",
	"/var/tmp/cydia.log",
	"/private/var/lib/cydia",
	"/private/var/tmp/cydia.log",
	"/private/jailbreak.txt",
	"/jb/jailbreakd.plist",
	"/jb/libjailbreak.dylib",
	"/jb/amfid_payload.dylib",
	"/.cydia_no_stash",
	"/usr/share/jailbreak",
	"/etc/apt/sources.list.d/cydia.list",
	NULL,
};

static bool string_equals(const char *left, const char *right)
{
	return left && right && strcmp(left, right) == 0;
}

static size_t path_length_without_trailing_separators(const char *path)
{
	if (!path) return 0;
	size_t length = strlen(path);
	while (length > 1U && path[length - 1U] == '/') length--;
	return length;
}

static bool path_equals_ignoring_trailing_separators(const char *left, const char *right)
{
	if (!left || !right) return false;
	const size_t left_length = path_length_without_trailing_separators(left);
	const size_t right_length = path_length_without_trailing_separators(right);
	return left_length == right_length && memcmp(left, right, left_length) == 0;
}

static bool string_has_prefix(const char *value, const char *prefix)
{
	return value && prefix && strncmp(value, prefix, strlen(prefix)) == 0;
}

static const char *path_basename(const char *path)
{
	if (!path || path[0] == '\0') {
		return NULL;
	}

	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

static bool basename_is_hidden_loader(const char *basename)
{
	if (!basename || basename[0] == '\0') {
		return false;
	}

	/* Hash-suffixed systemhook images are intentional RootHide artifacts. */
	if (string_has_prefix(basename, "systemhook-")) {
		return true;
	}

	for (size_t index = 0; k_hidden_loader_basenames[index]; index++) {
		if (string_equals(basename, k_hidden_loader_basenames[index])) {
			return true;
		}
	}
	return false;
}

static bool path_has_jbroot_component(const char *path)
{
	if (!path || path[0] == '\0') {
		return false;
	}

	const char *component = path;
	while (component) {
		const char *slash = strchr(component, '/');
		size_t length = slash ? (size_t)(slash - component) : strlen(component);
		if ((length == sizeof(".jbroot") - 1 && memcmp(component, ".jbroot", length) == 0) ||
		    (length >= sizeof(".jbroot-") - 1 &&
		     memcmp(component, ".jbroot-", sizeof(".jbroot-") - 1) == 0)) {
			return true;
		}
		component = slash ? slash + 1 : NULL;
	}
	return false;
}

static const char *preboot_relative_path(const char *path)
{
	static const char k_preboot_prefix[] = "/private/preboot/";
	if (!string_has_prefix(path, k_preboot_prefix)) {
		return NULL;
	}
	return path + sizeof(k_preboot_prefix) - 1;
}

static bool component_equals(const char *component, size_t length, const char *expected)
{
	return strlen(expected) == length && memcmp(component, expected, length) == 0;
}

static bool component_has_prefix(const char *component, size_t length, const char *prefix)
{
	size_t prefix_length = strlen(prefix);
	return length >= prefix_length && memcmp(component, prefix, prefix_length) == 0;
}

/*
 * Match only the RootHide-owned portions of the preboot layout:
 *
 *   /private/preboot/{jb,procursus}/...
 *   /private/preboot/<hash>/{dopamine-*,jb-*,procursus,...}/...
 *
 * The bare preboot root and its active alias intentionally remain visible.
 */
static bool preboot_path_hidden(const char *path)
{
	const char *relative = preboot_relative_path(path);
	if (!relative || relative[0] == '\0') {
		return false;
	}

	const char *first_slash = strchr(relative, '/');
	size_t first_length = first_slash ? (size_t)(first_slash - relative) : strlen(relative);
	if (component_equals(relative, first_length, ".installed_palera1n")) {
		/* A marker file is exact; do not infer a directory below it. */
		return first_slash == NULL;
	}
	if (component_equals(relative, first_length, "jb") ||
	    component_equals(relative, first_length, "procursus")) {
		return true;
	}

	/* The next component is at the immediate child level of a preboot hash. */
	if (!first_slash || first_slash[1] == '\0') {
		return false;
	}
	const char *second = first_slash + 1;
	const char *second_slash = strchr(second, '/');
	size_t second_length = second_slash ? (size_t)(second_slash - second) : strlen(second);
	return component_has_prefix(second, second_length, "dopamine-") ||
	       component_has_prefix(second, second_length, "jb-") ||
	       component_equals(second, second_length, "procursus") ||
	       component_equals(second, second_length, ".installed_dopamine") ||
	       component_equals(second, second_length, ".installed_palera1n");
}

static bool path_is_known_hidden_filesystem_path(const char *path)
{
	for (size_t index = 0; k_hidden_filesystem_paths[index]; index++) {
		if (path_equals_ignoring_trailing_separators(path,
		                                             k_hidden_filesystem_paths[index])) {
			return true;
		}
	}
	return false;
}

static bool path_equals_parent_and_name(const char *path, const char *parent, const char *name)
{
	const char *slash = strrchr(path, '/');
	if (!slash || !name || strcmp(slash + 1, name) != 0) {
		return false;
	}

	/* A trailing slash on the parent does not change its lexical directory. */
	size_t parent_length = strlen(parent);
	while (parent_length > 1 && parent[parent_length - 1] == '/') {
		parent_length--;
	}
	return parent_length == (size_t)(slash - path) &&
	       memcmp(parent, path, parent_length) == 0;
}

static bool directory_entry_name_is_valid(const char *name)
{
	return name && name[0] != '\0' && strcmp(name, ".") != 0 &&
	       strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

static bool path_hides_descendants(const char *path)
{
	/* Exact marker files and generic exact paths do not imply a subtree. */
	return path_has_jbroot_component(path) || preboot_path_hidden(path);
}

static bool path_is_preboot_hash_root(const char *path)
{
	const char *relative = preboot_relative_path(path);
	if (!relative || relative[0] == '\0') {
		return false;
	}

	const char *slash = strchr(relative, '/');
	/* A single trailing slash is still the same lexical directory. */
	return !slash || slash[1] == '\0';
}

bool rhi_hider_image_path_hidden(const char *path)
{
	if (!path || path[0] == '\0') {
		return false;
	}
	return path_has_jbroot_component(path) ||
	       basename_is_hidden_loader(path_basename(path));
}

bool rhi_hider_filesystem_path_hidden(const char *path)
{
	if (!path || path[0] == '\0') {
		return false;
	}
	return rhi_hider_image_path_hidden(path) || preboot_path_hidden(path) ||
	       path_is_known_hidden_filesystem_path(path);
}

bool rhi_hider_directory_entry_hidden(const char *parent_path, const char *name)
{
	if (!parent_path || !directory_entry_name_is_valid(name)) {
		return false;
	}

	/* A real hidden directory carries its entire lexical subtree with it. */
	if (path_hides_descendants(parent_path)) {
		return true;
	}

	/* Image artifacts use a basename rule in every parent directory. */
	if (rhi_hider_image_path_hidden(name)) {
		return true;
	}

	/* Match known exact filesystem probes without constructing a new path. */
	for (size_t index = 0; k_hidden_filesystem_paths[index]; index++) {
		if (path_equals_parent_and_name(k_hidden_filesystem_paths[index], parent_path, name)) {
			return true;
		}
	}

	/* Direct RootHide markers below /private/preboot, but not active itself. */
	if ((string_equals(parent_path, "/private/preboot") ||
	     string_equals(parent_path, "/private/preboot/")) &&
	    (string_equals(name, ".installed_palera1n") || string_equals(name, "jb") ||
	     string_equals(name, "procursus"))) {
		return true;
	}

	/* A one-component child of preboot is a hash root (including "active"). */
	if (path_is_preboot_hash_root(parent_path)) {
		return string_has_prefix(name, "dopamine-") || string_has_prefix(name, "jb-") ||
	       string_equals(name, "procursus") || string_equals(name, ".installed_dopamine") ||
	       string_equals(name, ".installed_palera1n");
	}

	return false;
}

#import <Foundation/Foundation.h>

#include <errno.h>
#include <spawn.h>
#include <dlfcn.h>
#include <signal.h>
#include <libgen.h>
#include <sandbox.h>
#include <libproc.h>
#include <xpc/xpc.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <dispatch/dispatch.h>

#include "../libjailbreak.h"
#include "../codesign.h"
#include "../info.h"
#include "jailbreakd.h"
#include "common.h"
#include "log.h"

bool launchdhookFirstLoad = false;

// To replace dyld patch, make dyld respect DYLD_ environment variables
int proc_patch_csflags(pid_t pid)
{
    int ret = 0;
    uint64_t proc = proc_find(pid);
    if(proc) {
        proc_csflags_set(proc, CS_GET_TASK_ALLOW);
    } else {
        ret = -1;
    }
    return ret;
}

#define P_LTRACED       0x00000400      /* */
#define P_LNOATTACH     0x00001000      /* */
bool proc_cantrace(pid_t pid) {
    uint64_t proc = proc_find(pid);
    if (proc == 0) {
        return false;
    }
    uint64_t lflag_offset = koffsetof(proc, flag) + 4;
    uint32_t lflag = kread32(proc + lflag_offset);
    if ((lflag & (P_LTRACED|P_LNOATTACH)) != 0) {
        return false;
    }
    return true;
}

pid_t proc_get_ppid(pid_t pid)
{
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) != sizeof(procInfo)) {
        return -1;
    }
    return procInfo.pbi_ppid;
}

// #define PROC_PIDPATHINFO_MAXSIZE        (4*MAXPATHLEN)
char* proc_get_path(pid_t pid, char* buffer)
{
    static char __thread threadbuffer[PATH_MAX];
    if(!buffer) buffer = threadbuffer;
    int ret = proc_pidpath(pid, buffer, PATH_MAX); /* proc_pidpath is not always reliable, 
    it will return ENOENT if the original executable file of a running process is removed from disk (e.g.  upgrading/reinstalling a package) */
    if (ret <= 0) return NULL;
    return buffer;
}

struct proc_uniqidentifierinfo {
	uint8_t                 p_uuid[16];             /* UUID of the main executable */
	uint64_t                p_uniqueid;             /* 64 bit unique identifier for process */
	uint64_t                p_puniqueid;            /* unique identifier for process's parent */
	int32_t                 p_idversion;            /* pid version */
	uint32_t                p_reserve2;             /* reserved for future use */
	uint64_t                p_reserve3;             /* reserved for future use */
	uint64_t                p_reserve4;             /* reserved for future use */
};
#define PROC_PIDUNIQIDENTIFIERINFO      17
#define PROC_PIDUNIQIDENTIFIERINFO_SIZE (sizeof(struct proc_uniqidentifierinfo))
int proc_get_pidversion(pid_t pid)
{
	struct proc_uniqidentifierinfo uniqidinfo = {0};
	int ret = proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo));
	if (ret <= 0) {
        return 0;
	}
	return uniqidinfo.p_idversion;
}

/* Status values. */
#define SIDL    1               /* Process being created by fork. */
#define SRUN    2               /* Currently runnable. */
#define SSLEEP  3               /* Sleeping on an address. */
#define SSTOP   4               /* Process debugging or suspension. */
#define SZOMB   5               /* Awaiting collection by parent. */

int proc_paused(pid_t pid, bool* paused)
{
    *paused = false;

    struct proc_bsdinfo procInfo = {0};
    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
    if (ret != sizeof(procInfo)) {
        return -1;
    }

    if (procInfo.pbi_status == SSTOP) {
        *paused = true;
    } else if (procInfo.pbi_status != SRUN) {
        return -1;
    }

    return 0;
}

int unrestrict(pid_t pid, int (*callback)(pid_t), bool resume)
{
	while(true) {
		bool paused = false;
		if (proc_paused(pid, &paused) != 0) {
			JBLogError("Failed to check if process(%d) is paused", pid);
			return -1;
		}
		if(paused) {
			break;
		}
        usleep(10*1000);
	}

    int ret = callback(pid);
    if(ret != 0) {
        JBLogError("Failed to invoke callback for process %d: %d", pid, ret);
        return ret;
    }

    if (resume)
        kill(pid, SIGCONT);

    JBLogDebug("Unrestricted process %s pid:%d resume:%d", proc_get_path(pid,NULL), pid, resume);
    return 0;
}

bool process_force_dyld_patch(const char* path, const char** argv)
{
    if(!path && !argv) return false;

    if(__builtin_available(iOS 16.0, *))
    {
        if(string_has_suffix(path, "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.WebContent.xpc/com.apple.WebKit.WebContent")) {
            return true;
        }
        else if(strcmp(path, "/usr/libexec/xpcproxy")==0) {
            if (argv && argv[0] && argv[1] && string_has_prefix(argv[1], "com.apple.WebKit.WebContent")) {
                return true;
            }
        }
    }
    return false;
}

bool dyld_patch_enabled()
{
    return jbinfo(dyld_patch_enabled);
}

int roothide_patch_proc(pid_t pid)
{
    if(!dyld_patch_enabled()) {
        if(!process_force_dyld_patch(proc_get_path(pid,NULL), NULL)) {
            return proc_patch_csflags(pid);
        }
    }
    return proc_patch_dyld(pid);
}

int roothide_config_set_spinlock_fix(bool enabled)
{
    NSString* roothideDir = JBROOT_PATH(@"/var/mobile/Library/RootHide");
    if(![NSFileManager.defaultManager fileExistsAtPath:roothideDir]) {
        NSDictionary* attr = @{NSFilePosixPermissions:@(0755), NSFileOwnerAccountID:@(501), NSFileGroupOwnerAccountID:@(501)};
        if(![NSFileManager.defaultManager createDirectoryAtPath:roothideDir withIntermediateDirectories:YES attributes:attr error:nil])
        {
            JBLogError("Failed to create directory: %@", roothideDir);
            return -1;
        }
    }

    NSString *configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    NSMutableDictionary* defaults = [NSMutableDictionary dictionaryWithContentsOfFile:configFilePath];
    if(!defaults) defaults = [[NSMutableDictionary alloc] init];
    [defaults setValue:@(enabled) forKey:@"spinlockFixApplied"];
    if(![defaults writeToFile:configFilePath atomically:YES]) {
        JBLogError("Failed to write config file: %@", configFilePath);
        return -1;
    }
    return 0;
}

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
char* getAppUUIDPath(const char* path)
{
    if(!path) return NULL;

    char abspath[PATH_MAX];
    if(!realpath(path, abspath)) return NULL;

    if(strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NULL;

    char* p1 = abspath + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NULL;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NULL;
	
	*p2 = '\0';

	return strdup(abspath);
}

bool isRemovableBundlePath(const char* path)
{
    const char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;
	free((void*)uuidpath);
	return true;
}

bool hasTrollstoreMarker(const char* path)
{
    char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;

	char* markerpath=NULL;
	asprintf(&markerpath, "%s/_TrollStore", uuidpath);

	int ret = access(markerpath, F_OK);
    if(ret != 0) {
        free((void*)markerpath); markerpath = NULL;
        asprintf(&markerpath, "%s/_TrollStoreLite", uuidpath);
        ret = access(markerpath, F_OK);
    }

    free((void*)markerpath);
	free((void*)uuidpath);

	return ret==0;
}

bool hasTrollstoreLiteMarker(const char* path)
{
    char* uuidpath = getAppUUIDPath(path);
	if(!uuidpath) return false;

	char* markerpath=NULL;
	asprintf(&markerpath, "%s/_TrollStoreLite", uuidpath);

	int ret = access(markerpath, F_OK);

    free((void*)markerpath);
	free((void*)uuidpath);

	return ret==0;
}

bool isSubPathOf(const char* parent, const char* child)
{
	char real_child[PATH_MAX]={0};
	char real_parent[PATH_MAX]={0};

	if(!realpath(child, real_child)) return false;
	if(!realpath(parent, real_parent)) return false;

	if(!string_has_prefix(real_child, real_parent))
		return false;

	return real_child[strlen(real_parent)] == '/';
}

void ensure_jbroot_symlink(const char* filepath)
{
	JBLogDebug("ensure_jbroot_symlink: %s", filepath);

	if(access(filepath, F_OK) !=0 )
		return;

	char realfpath[PATH_MAX]={0};
	assert(realpath(filepath, realfpath) != NULL);

	char realdirpath[PATH_MAX+1]={0};
	dirname_r(realfpath, realdirpath);
	if(realdirpath[0] && realdirpath[strlen(realdirpath)-1] != '/') {
		strlcat(realdirpath, "/", sizeof(realdirpath));
	}

	char jbrootpath[PATH_MAX+1]={0};
	assert(realpath(JBROOT_PATH("/"), jbrootpath) != NULL);
	if(jbrootpath[0] && jbrootpath[strlen(jbrootpath)-1] != '/') {
		strlcat(jbrootpath, "/", sizeof(jbrootpath));
	}

	JBLogDebug("%s : %s", realdirpath, jbrootpath);

	if(strncmp(realdirpath, jbrootpath, strlen(jbrootpath)) != 0) 
		return;

	struct stat jbrootst;
	assert(stat(jbrootpath, &jbrootst) == 0);
	
	char sympath[PATH_MAX];
	snprintf(sympath,sizeof(sympath),"%s/.jbroot", realdirpath);

	struct stat symst;
	if(lstat(sympath, &symst)==0)
	{
		if(S_ISLNK(symst.st_mode))
		{
			if(stat(sympath, &symst) == 0)
			{
				if(symst.st_dev==jbrootst.st_dev 
					&& symst.st_ino==jbrootst.st_ino)
					return;
			}

			assert(unlink(sympath) == 0);
			
		} else {
			//not a symlink? just let it go
			return;
		}
	}

	if(symlink(jbrootpath, sympath) ==0 ) {
		JBLogDebug("update .jbroot @ %s\n", sympath);
	} else {
		JBLogError("symlink error @ %s\n", sympath);
	}
}

char* generate_sandbox_extensions(audit_token_t *processToken, bool writable)
{
    char* sandboxExtensionsOut=NULL;

    char jbroot_base[PATH_MAX];
    char jbroot_writable[PATH_MAX];
    snprintf(jbroot_base, sizeof(jbroot_base), "/private/var/containers/Bundle/Application/.jbroot-%016llX/", jbinfo(jbrand));
    snprintf(jbroot_writable, sizeof(jbroot_writable), "/private/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX/", jbinfo(jbrand));

    char* fileclass = writable ? "com.apple.app-sandbox.read-write" : "com.apple.app-sandbox.read";
    char *extension1 = sandbox_extension_issue_file_to_process(fileclass, jbroot_writable, 0, *processToken);

    char *extension2 = sandbox_extension_issue_file_to_process("com.apple.app-sandbox.read", jbroot_base, 0, *processToken);
    char *extension3 = sandbox_extension_issue_file_to_process("com.apple.sandbox.executable", jbroot_base, 0, *processToken);

    if(extension1 && extension2 && extension3) {
        asprintf(&sandboxExtensionsOut, "%s|%s|%s", extension1, extension2, extension3);
    }
    
    if (extension1) free(extension1);
    if (extension2) free(extension2);
    if (extension3) free(extension3);

    return sandboxExtensionsOut;
}

void hideDeveloperMode()
{
    uint64_t launch_env_logging = kread64(ksymbol(launch_env_logging));
    uint64_t developer_mode_status = kread64(ksymbol(developer_mode_status));
    kwrite64(ksymbol(launch_env_logging), developer_mode_status);
    kwrite64(ksymbol(developer_mode_status), launch_env_logging);
}

int randomizeAndLoadBasebinTrustcache(const char* basebinPath)
{
    cdhash_t* basebins_cdhashes=NULL;
    uint32_t basebins_cdhashesCount=0;

    NSDirectoryEnumerator<NSURL *> *directoryEnumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:@(basebinPath)] includingPropertiesForKeys:nil options:0 errorHandler:nil];
    if(!directoryEnumerator) {
        return -1;
    }
    for(NSURL* fileURL in directoryEnumerator)
    {
        cdhash_t cdhash={0};
        if(ensure_randomized_cdhash(fileURL.path.fileSystemRepresentation, cdhash) == 0) {
            basebins_cdhashes = realloc(basebins_cdhashes, (basebins_cdhashesCount+1) * sizeof(cdhash_t));
            memcpy(&basebins_cdhashes[basebins_cdhashesCount], cdhash, sizeof(cdhash_t));
            basebins_cdhashesCount++;
        }
    }

    if(!basebins_cdhashes) {
        return -2;
    }

    trustcache_file_v1 *basebinTcFile = NULL;
    int r1 = trustcache_file_build_from_cdhashes(basebins_cdhashes, basebins_cdhashesCount, &basebinTcFile);
    free(basebins_cdhashes);
    if (r1 != 0) {
        return -3;
    }

    int r2 = trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID);
    free(basebinTcFile);
    if (r2 != 0) {
        return -4;
    }

    return 0;
}

kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);

bool otherJailbreakActived()
{
    if(jbclient_roothide_jailbroken())
    {
        return false;
    }

    // // may be palehide
    // uint32_t csFlags = 0;
    // csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
    // if(csFlags & CS_PLATFORM_BINARY)
    // {
    //     if(!builtint_palehide_test()) {
    //         return true;
    //     }
    // }

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.opa334.jailbreakd", &port);
    if(kr == KERN_SUCCESS) {
        return true; // roothide dopamine 1.x
    }

    const char* rootpath = jbclient_get_jbroot();
    if(rootpath && strlen(rootpath) > 0) {
        return true;
    }

    if(access("/dev/md0", F_OK)==0) {
        return true;
    }

    if(access("/dev/rmd0", F_OK)==0) {
        return true;
    }

    struct statfs fs;
    int sfsret = statfs("/usr/lib", &fs);
    if (sfsret == 0) {
        if(strcmp(fs.f_mntonname, "/usr/lib")==0) {
            return true;
        }
    }

    return false;
}

#define RB_QUICK	0x400
#define RB_PANIC	0x800
int reboot_np(int howto, const char *message);
void launchd_panic(const char* fmt, ...)
{
    char* reason = NULL;

	va_list args;
	va_start(args, fmt);
	vasprintf(&reason, fmt, args);
	va_end(args);

    JBLogError("launchd panic: %s", reason);
    reboot_np(RB_QUICK | RB_PANIC, reason);
    __asm("brk #0x1234");
    _exit(0);
}

static bool exec_patch_enabled = true;
void exec_set_patch(bool enabled)
{
	exec_patch_enabled = enabled;
}
int exec_cmd_roothide_spawn(pid_t* pidp, const char* path, const posix_spawn_file_actions_t *fap, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
    posix_spawnattr_t attr = NULL;
    if(!attrp) {
        posix_spawnattr_init(&attr);
        attrp = &attr;
    }

    int argc = 0;
    for(int i=0; argv && argv[i]; i++) {
        argc++;
    }

    bool need_patch_child = exec_patch_enabled;
    if(dlopen("systemhook.dylib", RTLD_NOLOAD)) {
    /* if systemhook has been loaded into the current process, 
        it means posix_spawn has been hooked and we can skip patching. */
        need_patch_child = false;
    } else if(argc==3 && strcmp(argv[1],"trollstore")==0 && strcmp(argv[2],"delete-bootstrap")==0) {
        // skip patching for trollstore bootstrap delete
        need_patch_child = false;
    }

    if(need_patch_child && !dyld_patch_enabled()) {
        if(jbclient_trust_executable_recurse(path, NULL) != 0) {
            JBLogError("Failed to trust executable: %s", path);
            return 999;
        }
    }

    short flags=0;
    posix_spawnattr_getflags(attrp, &flags);
    bool should_resume = (flags & POSIX_SPAWN_START_SUSPENDED) == 0;

    JBLogDebug("exec_cmd_roothide_spawn path=%s flags=%x", path, flags);
    if (argv) for (int i = 0; argv[i]; i++) JBLogDebug("\targs[%d] = %s", i, argv[i]);
    if (envp) for (int i = 0; envp[i]; i++) JBLogDebug("\tenvp[%d] = %s", i, envp[i]);

    posix_spawnattr_setflags(attrp, flags | POSIX_SPAWN_START_SUSPENDED);

    pid_t pid = 0;
    int ret = posix_spawn(&pid, path, fap, attrp, argv, envp);
    if(pidp) *pidp = pid;

    JBLogDebug("spawn ret=%d pid=%d", ret, pid);

    if(ret == 0 && pid > 0) 
    {
        if(need_patch_child) {
            // will fail before launchdhook injected and dyld patched, eg: opainject...
            if(jbdSpawnPatchChild(pid, should_resume) != 0) {
                JBLogError("Failed to patch spawned process (%d) %s", pid, path);
                return 999;
            }
        } else {
            if (should_resume) {
                kill(pid, SIGCONT);
            }
        }
    }

    if(attr) {
        posix_spawnattr_destroy(&attr);
        attrp = NULL;
    }

    return ret;
}

int ensure_dyld_trustcache(const char* path)
{
    JBLogDebug("trusting dyld file: %s", path);

    cdhash_t cdhash = {0};
    if(ensure_randomized_cdhash(path, cdhash) != 0) {
        JBLogError("Error: failed to ensure randomized cdhash: %s\n", path);
        return -1;
    }

    if(is_cdhash_trustcached(cdhash)) {
        JBLogDebug("dyld file already trusted: %s", path);
        return 0;
    }

    trustcache_file_v1 *dyldTCFile = NULL;
    if (trustcache_file_build_from_cdhashes(cdhash, 1, &dyldTCFile) != 0) {
        JBLogError("Failed to build dyld trustcache");
        return -1;
    }

    if (trustcache_file_upload_with_uuid(dyldTCFile, DYLD_TRUSTCACHE_UUID) != 0) {
        JBLogError("Failed to upload dyld trustcache");
        free(dyldTCFile);
        return -1;
    }

    free(dyldTCFile);
    return 0;
}

#define RB2_USERREBOOT (0x2000000000000000llu)
void check_usreboot_msg(xpc_object_t xmsg)
{
	if(xpc_dictionary_get_uint64(xmsg, "flags") != RB2_USERREBOOT) {
		return;
	}
	if(xpc_dictionary_get_uint64(xmsg, "type") != 1) {
		return;
	}
	if(!xpc_dictionary_get_value(xmsg, "handle")
     || xpc_dictionary_get_uint64(xmsg, "handle") != 0) {
		return;
	}
	
	if(getpid() != 1) {
		JBLogError("usereboot message not from launchd?");
		return;
	}

	audit_token_t clientToken = {0};
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

	if(audit_token_to_euid(clientToken) != 0) {
		JBLogError("usereboot message not from root process?");
		return;
	}

	struct statfs fsb={0};
	if (statfs("/Developer", &fsb) != 0) {
		JBLogError("unable to statfs /Developer, already broken?");
		return;
	}

	if(strcmp(fsb.f_mntonname, "/Developer") != 0) {
		JBLogDebug("/Developer not mounted. skip");
		return;
	}

	// fix Xcode debugging being broken after the userspace reboot
	// for iOS15 it is too late by the time launchd re-execs itself

	int retval = unmount("/Developer", MNT_FORCE);

	if(retval != 0) {
		JBLogError("unmount /Developer : %d %d,%s", retval, errno, strerror(errno));
	}
}

void roothide_handler_jbserver_msg(xpc_object_t xmsg)
{
    check_usreboot_msg(xmsg);

#ifdef ENABLE_LOGS

	if (!xpc_dictionary_get_value(xmsg, "jb-domain")) return;
	if (!xpc_dictionary_get_value(xmsg, "action")) return;

	audit_token_t clientToken = { 0 };
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

    const char* desc = NULL;
    JBLogDebug("jbserver received xpc message from (%d) %s :\n%s", 
        audit_token_to_pid(clientToken), 
        proc_get_path(audit_token_to_pid(clientToken),NULL), 
        (desc=xpc_copy_description(xmsg)));
    if(desc) free((void*)desc);

#endif
}

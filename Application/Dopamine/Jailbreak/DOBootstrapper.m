//
//  Bootstrapper.m
//  Dopamine
//
//  Created by Lars Fröder on 09.01.24.
//

#import "DOBootstrapper.h"
#import "DOEnvironmentManager.h"
#import "DOUIManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import "zstd.h"
#import <sys/mount.h>
#import <stdio.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import "NSString+Version.h"

#define LIBKRW_DOPAMINE_BUNDLED_VERSION @"2.0.3"
#define LIBROOT_DOPAMINE_BUNDLED_VERSION @"1.0.1"
#define BASEBIN_LINK_BUNDLED_VERSION @"1.0.0"
#define ROOTHIDE_CORE_BUNDLED_VERSION @"0.1.0-0+opamine1"
#define SILEO_BUNDLED_VERSION @"2.5.1-13+opamine1"

static NSDictionary *gBundledPackages = @{
    @"libkrw0-dopamine" : LIBKRW_DOPAMINE_BUNDLED_VERSION,
    @"libroot-dopamine" : LIBROOT_DOPAMINE_BUNDLED_VERSION,
    @"dopamine-basebin-link" : BASEBIN_LINK_BUNDLED_VERSION,
    @"roothide" : ROOTHIDE_CORE_BUNDLED_VERSION,
    @"org.coolstar.sileo" : SILEO_BUNDLED_VERSION,
};

struct hfs_mount_args {
    char    *fspec;
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    uint32_t hfs_encoding;        /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

NSString *const bootstrapErrorDomain = @"BootstrapErrorDomain";
typedef NS_ENUM(NSInteger, JBErrorCode) {
    BootstrapErrorCodeFailedToGetURL            = -1,
    BootstrapErrorCodeFailedToDownload          = -2,
    BootstrapErrorCodeFailedDecompressing       = -3,
    BootstrapErrorCodeFailedExtracting          = -4,
    BootstrapErrorCodeFailedRemount             = -5,
    BootstrapErrorCodeFailedFinalising          = -6,
    BootstrapErrorCodeFailedReplacing           = -7,
};

#define BUFFER_SIZE 8192

@interface DOEnvironmentManager (DOBootstrapperPrivate)
- (NSString *)activePrebootPath;
@end

@implementation DOBootstrapper

- (instancetype)init
{
    self = [super init];
    if (self) {
        /*NSURLSessionConfiguration *config = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier:@"com.opa334.bootstrapper.background-session"];
        _urlSession = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];*/
    }
    return self;
}

- (NSError *)decompressZstd:(NSString *)zstdPath toTar:(NSString *)tarPath
{
    // Open the input file for reading
    FILE *input_file = fopen(zstdPath.fileSystemRepresentation, "rb");
    if (input_file == NULL) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to open input file %@: %s", zstdPath, strerror(errno)]}];
    }

    // Open the output file for writing
    FILE *output_file = fopen(tarPath.fileSystemRepresentation, "wb");
    if (output_file == NULL) {
        fclose(input_file);
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to open output file %@: %s", tarPath, strerror(errno)]}];
    }

    // Create a ZSTD decompression context
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (dctx == NULL) {
        fclose(input_file);
        fclose(output_file);
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to create ZSTD decompression context"}];
    }

    // Create a buffer for reading input data
    uint8_t *input_buffer = (uint8_t *) malloc(BUFFER_SIZE);
    if (input_buffer == NULL) {
        ZSTD_freeDCtx(dctx);
        fclose(input_file);
        fclose(output_file);
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to allocate input buffer"}];
    }

    // Create a buffer for writing output data
    uint8_t *output_buffer = (uint8_t *) malloc(BUFFER_SIZE);
    if (output_buffer == NULL) {
        free(input_buffer);
        ZSTD_freeDCtx(dctx);
        fclose(input_file);
        fclose(output_file);
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to allocate output buffer"}];
    }

    // Create a ZSTD decompression stream
    ZSTD_inBuffer in = {0};
    ZSTD_outBuffer out = {0};
    ZSTD_DStream *dstream = ZSTD_createDStream();
    if (dstream == NULL) {
        free(output_buffer);
        free(input_buffer);
        ZSTD_freeDCtx(dctx);
        fclose(input_file);
        fclose(output_file);
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : @"Failed to create ZSTD decompression stream"}];
    }

    // Initialize the ZSTD decompression stream
    size_t ret = ZSTD_initDStream(dstream);
    if (ZSTD_isError(ret)) {
        ZSTD_freeDStream(dstream);
        free(output_buffer);
        free(input_buffer);
        ZSTD_freeDCtx(dctx);
        fclose(input_file);
        fclose(output_file);
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to initialize ZSTD decompression stream: %s", ZSTD_getErrorName(ret)]}];
    }

    // Read and decompress the input file
    size_t total_bytes_read = 0;
    size_t total_bytes_written = 0;
    size_t bytes_read;
    size_t bytes_written;
    while (1) {
        // Read input data into the input buffer
        bytes_read = fread(input_buffer, 1, BUFFER_SIZE, input_file);
        if (bytes_read == 0) {
            if (feof(input_file)) {
                // End of input file reached, break out of loop
                break;
            } else {
                ZSTD_freeDStream(dstream);
                free(output_buffer);
                free(input_buffer);
                ZSTD_freeDCtx(dctx);
                fclose(input_file);
                fclose(output_file);
                return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to read input file: %s", strerror(errno)]}];
            }
        }

        in.src = input_buffer;
        in.size = bytes_read;
        in.pos = 0;

        while (in.pos < in.size) {
            // Initialize the output buffer
            out.dst = output_buffer;
            out.size = BUFFER_SIZE;
            out.pos = 0;

            // Decompress the input data
            ret = ZSTD_decompressStream(dstream, &out, &in);
            if (ZSTD_isError(ret)) {
                ZSTD_freeDStream(dstream);
                free(output_buffer);
                free(input_buffer);
                ZSTD_freeDCtx(dctx);
                fclose(input_file);
                fclose(output_file);
                return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to decompress input data: %s", ZSTD_getErrorName(ret)]}];
            }

            // Write the decompressed data to the output file
            bytes_written = fwrite(output_buffer, 1, out.pos, output_file);
            if (bytes_written != out.pos) {
                ZSTD_freeDStream(dstream);
                free(output_buffer);
                free(input_buffer);
                ZSTD_freeDCtx(dctx);
                fclose(input_file);
                fclose(output_file);
                return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedDecompressing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to write output file: %s", strerror(errno)]}];
            }

            total_bytes_written += bytes_written;
        }

        total_bytes_read += bytes_read;
    }

    // Clean up resources
    ZSTD_freeDStream(dstream);
    free(output_buffer);
    free(input_buffer);
    ZSTD_freeDCtx(dctx);
    fclose(input_file);
    fclose(output_file);

    return nil;
}

- (NSError *)extractTar:(NSString *)tarPath toPath:(NSString *)destinationPath
{
    int r = libarchive_unarchive(tarPath.fileSystemRepresentation, destinationPath.fileSystemRepresentation);
    if (r != 0) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"libarchive returned %d", r]}];
    }
    return nil;
}

- (BOOL)deleteSymlinkAtPath:(NSString *)path error:(NSError **)error
{
    NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:error];
    if (!attributes) return YES;
    if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
        return [[NSFileManager defaultManager] removeItemAtPath:path error:error];
    }
    return NO;
}

- (BOOL)fileOrSymlinkExistsAtPath:(NSString *)path
{
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return YES;
    
    NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (attributes) {
        if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
            return YES;
        }
    }
    
    return NO;
}

- (NSError *)createSymlinkAtPath:(NSString *)path toPath:(NSString *)destinationPath createIntermediateDirectories:(BOOL)createIntermediate
{
    NSError *error;
    NSString *parentPath = [path stringByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] fileExistsAtPath:parentPath]) {
        if (!createIntermediate) return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed create %@->%@ symlink: Parent dir does not exists", path, destinationPath]}];
        if (![[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error]) return error;
    }
    
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:path withDestinationPath:destinationPath error:&error];
    return error;
}

#if 0
- (BOOL)isPrivatePrebootMountedWritable
{
    struct statfs ppStfs;
    statfs("/private/preboot", &ppStfs);
    return !(ppStfs.f_flags & MNT_RDONLY);
}

- (int)remountPrivatePrebootWritable:(BOOL)writable
{
    struct statfs ppStfs;
    int r = statfs("/private/preboot", &ppStfs);
    if (r != 0) return r;
    
    uint32_t flags = MNT_UPDATE;
    if (!writable) {
        flags |= MNT_RDONLY;
    }
    struct hfs_mount_args mntargs =
    {
        .fspec = ppStfs.f_mntfromname,
        .hfs_mask = 0,
    };
    return mount("apfs", "/private/preboot", flags, &mntargs);
}

- (NSError *)ensurePrivatePrebootIsWritable
{
    if (![self isPrivatePrebootMountedWritable]) {
        int r = [self remountPrivatePrebootWritable:YES];
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedRemount userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Remounting /private/preboot as writable failed with error: %s", strerror(errno)]}];
        }
    }
    return nil;
}

- (void)fixupPathPermissions
{
    // Ensure the following paths are owned by root:wheel and have permissions of 755:
    // /private
    // /private/preboot
    // /private/preboot/UUID
    // /private/preboot/UUID/dopamine-<UUID>
    // /private/preboot/UUID/dopamine-<UUID>/procursus

    NSString *tmpPath = JBROOT_PATH(@"/");
    while (![tmpPath isEqualToString:@"/"]) {
        struct stat s;
        stat(tmpPath.fileSystemRepresentation, &s);
        if (s.st_uid != 0 || s.st_gid != 0) {
            chown(tmpPath.fileSystemRepresentation, 0, 0);
        }
        if ((s.st_mode & S_IRWXU) != 0755) {
            chmod(tmpPath.fileSystemRepresentation, 0755);
        }
        tmpPath = [tmpPath stringByDeletingLastPathComponent];
    }
}
#endif

- (void)patchBasebinDaemonPlist:(NSString *)plistPath
{
    NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (plistDict) {
        bool madeChanges = NO;
        NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
        for (NSString *argument in [programArguments reverseObjectEnumerator]) {
            if ([argument containsString:@"@JBROOT@"]) {
                programArguments[[programArguments indexOfObject:argument]] = [argument stringByReplacingOccurrencesOfString:@"@JBROOT@" withString:JBROOT_PATH(@"/")];
                madeChanges = YES;
            }
        }
        if (madeChanges) {
            plistDict[@"ProgramArguments"] = programArguments.copy;
            [plistDict writeToFile:plistPath atomically:NO];
        }
    }
}

- (void)patchBasebinDaemonPlists
{
    NSURL *basebinDaemonsURL = [NSURL fileURLWithPath:JBROOT_PATH(@"/basebin/LaunchDaemons")];
    for (NSURL *basebinDaemonURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:basebinDaemonsURL includingPropertiesForKeys:nil options:0 error:nil]) {
        [self patchBasebinDaemonPlist:basebinDaemonURL.path];
    }
}

#if 0
- (NSString *)bootstrapVersion
{
    uint64_t cfver = (((uint64_t)kCFCoreFoundationVersionNumber / 100) * 100);
    if (cfver >= 2000) {
        return nil;
    }
    return [NSString stringWithFormat:@"%llu", cfver];
}

- (NSURL *)bootstrapURL
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"https://apt.procurs.us/bootstraps/%@/bootstrap-ssh-iphoneos-arm64.tar.zst", [self bootstrapVersion]]];
}

/*- (void)downloadBootstrapWithCompletion:(void (^)(NSString *path, NSError *error))completion
{
    NSURL *bootstrapURL = [self bootstrapURL];
    if (!bootstrapURL) {
        completion(nil, [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedToGetURL userInfo:@{NSLocalizedDescriptionKey : @"Failed to obtain bootstrap URL"}]);
        return;
    }
    
    _downloadCompletionBlock = ^(NSURL * _Nullable location, NSError * _Nullable error) {
        NSError *ourError;
        if (error) {
            ourError = [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedToDownload userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to download bootstrap: %@", error.localizedDescription]}];
        }
        completion(location.path, ourError);
    };
    
    _bootstrapDownloadTask = [_urlSession downloadTaskWithURL:bootstrapURL];
    [_bootstrapDownloadTask resume];
}*/

- (void)extractBootstrap:(NSString *)path withCompletion:(void (^)(NSError *))completion
{
    NSString *bootstrapTar = [@"/var/tmp" stringByAppendingPathComponent:@"bootstrap.tar"];
    NSError *decompressionError = [self decompressZstd:path toTar:bootstrapTar];
    if (decompressionError) {
        completion(decompressionError);
        return;
    }
    
    decompressionError = [self extractTar:bootstrapTar toPath:@"/"];
    if (decompressionError) {
        completion(decompressionError);
        return;
    }
    
    [[NSData data] writeToFile:JBROOT_PATH(@"/.installed_dopamine") atomically:YES];
    completion(nil);
}

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion
{
    [[DOUIManager sharedInstance] sendLog:@"Updating BaseBin" debug:NO];

    // Ensure /private/preboot is mounted writable (Not writable by default on iOS <=15)
    NSError *error = [self ensurePrivatePrebootIsWritable];
    if (error) {
        completion(error);
        return;
    }
    
    [self fixupPathPermissions];
    
    // Remove /var/jb as it might be wrong
    if (![self deleteSymlinkAtPath:@"/var/jb" error:&error]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
            if (![[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:&error]) {
                completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb directory failed with error: %@", error]}]);
                return;
            }
        }
        else {
            completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb symlink failed with error: %@", error]}]);
            return;
        }
    }
    
    // Clean up xinaA15 v1 leftovers if desired
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/.keep_symlinks"]) {
        NSArray *xinaLeftoverSymlinks = @[
            @"/var/alternatives",
            @"/var/ap",
            @"/var/apt",
            @"/var/bin",
            @"/var/bzip2",
            @"/var/cache",
            @"/var/dpkg",
            @"/var/etc",
            @"/var/gzip",
            @"/var/lib",
            @"/var/Lib",
            @"/var/libexec",
            @"/var/Library",
            @"/var/LIY",
            @"/var/Liy",
            @"/var/local",
            @"/var/newuser",
            @"/var/profile",
            @"/var/sbin",
            @"/var/suid_profile",
            @"/var/sh",
            @"/var/sy",
            @"/var/share",
            @"/var/ssh",
            @"/var/sudo_logsrvd.conf",
            @"/var/suid_profile",
            @"/var/sy",
            @"/var/usr",
            @"/var/zlogin",
            @"/var/zlogout",
            @"/var/zprofile",
            @"/var/zshenv",
            @"/var/zshrc",
            @"/var/log/dpkg",
            @"/var/log/apt",
        ];
        NSArray *xinaLeftoverFiles = @[
            @"/var/lib",
            @"/var/master.passwd"
        ];
        
        for (NSString *xinaLeftoverSymlink in xinaLeftoverSymlinks) {
            [self deleteSymlinkAtPath:xinaLeftoverSymlink error:nil];
        }
        
        for (NSString *xinaLeftoverFile in xinaLeftoverFiles) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:xinaLeftoverFile]) {
                [[NSFileManager defaultManager] removeItemAtPath:xinaLeftoverFile error:nil];
            }
        }
    }
    
    NSString *basebinPath = JBROOT_PATH(@"/basebin");
    NSString *installedPath = JBROOT_PATH(@"/.installed_dopamine");
    error = [self createSymlinkAtPath:@"/var/jb" toPath:JBROOT_PATH(@"/") createIntermediateDirectories:YES];
    if (error) {
        completion(error);
        return;
    }
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:basebinPath]) {
        if (![[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
            BOOL recovered = NO;
            NSString *corruptedFilePath = JBROOT_PATH(@"/basebin/gen/dyld.old");
            NSString *jbrootPath = JBROOT_PATH(@"/");
            NSString *activePrebootPath = [[DOEnvironmentManager sharedManager] activePrebootPath];
            NSString *activePrebootPrefix = [activePrebootPath stringByAppendingString:@"/"];

            // Keep the recovery inside the active RootHide preboot volume.
            // /var/jb is only a compatibility symlink and must not be used to
            // locate either the corrupt file or the orphan destination.
            if (corruptedFilePath.length > 0
                && jbrootPath.length > 0
                && activePrebootPath.length > 0
                && [jbrootPath hasPrefix:activePrebootPrefix]
                && [[NSFileManager defaultManager] fileExistsAtPath:corruptedFilePath]
                && ![[NSFileManager defaultManager] removeItemAtPath:corruptedFilePath error:nil]) {
                // A failed update can leave dyld.old in a state that cannot be
                // deleted but can be moved out of basebin, allowing extraction
                // to rebuild the generated dyld from scratch.
                NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                NSString *orphanedPath = nil;
                for (NSUInteger attempt = 0; attempt < 4; attempt++) {
                    NSMutableString *randomString = [NSMutableString stringWithCapacity:6];
                    for (NSUInteger index = 0; index < 6; index++) {
                        NSUInteger randomIndex = arc4random_uniform((uint32_t)characterSet.length);
                        [randomString appendFormat:@"%C", [characterSet characterAtIndex:randomIndex]];
                    }

                    NSString *candidatePath = [activePrebootPath stringByAppendingPathComponent:[NSString stringWithFormat:@"orphaned-%@", randomString]];
                    if (![[NSFileManager defaultManager] fileExistsAtPath:candidatePath]) {
                        orphanedPath = candidatePath;
                        break;
                    }
                }

                if (orphanedPath
                    && [[NSFileManager defaultManager] moveItemAtPath:corruptedFilePath toPath:orphanedPath error:nil]
                    && [[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
                    recovered = YES;
                    error = nil;
                }
            }

            if (!recovered) {
                completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed deleting existing basebin file with error: %@", error.localizedDescription]}]);
                return;
            }
        }
    }
    error = [self extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:JBROOT_PATH(@"/")];
    if (error) {
        completion(error);
        return;
    }
    NSString *basebinMD5Path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.md5"];
    NSString *installedBasebinMD5Path = JBROOT_PATH(@"/basebin/.basebin_md5");
    if ([[NSFileManager defaultManager] fileExistsAtPath:basebinMD5Path]) {
        [[NSFileManager defaultManager] removeItemAtPath:installedBasebinMD5Path error:nil];
        [[NSFileManager defaultManager] copyItemAtPath:basebinMD5Path toPath:installedBasebinMD5Path error:nil];
    }
    [self patchBasebinDaemonPlists];
    [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/basebin/basebin.tc") error:nil];
    
    void (^bootstrapFinishedCompletion)(NSError *) = ^(NSError *error){
        if (error) {
            completion(error);
            return;
        }
        
        NSString *defaultSources = @"Types: deb\n"
            @"URIs: https://repo.chariz.com/\n"
            @"Suites: ./\n"
            @"Components:\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: https://havoc.app/\n"
            @"Suites: ./\n"
            @"Components:\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: http://apt.thebigboss.org/repofiles/cydia/\n"
            @"Suites: stable\n"
            @"Components: main\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: https://ellekit.space/\n"
            @"Suites: ./\n"
            @"Components:\n";
        [defaultSources writeToFile:JBROOT_PATH(@"/etc/apt/sources.list.d/default.sources") atomically:NO encoding:NSUTF8StringEncoding error:nil];
        
        NSString *mobilePreferencesPath = JBROOT_PATH(@"/var/mobile/Library/Preferences");
        if (![[NSFileManager defaultManager] fileExistsAtPath:mobilePreferencesPath]) {
            NSDictionary<NSFileAttributeKey, id> *attributes = @{
                NSFilePosixPermissions : @0755,
                NSFileOwnerAccountID : @501,
                NSFileGroupOwnerAccountID : @501,
            };
            [[NSFileManager defaultManager] createDirectoryAtPath:mobilePreferencesPath withIntermediateDirectories:YES attributes:attributes error:nil];
        }
        
        JBFixMobilePermissions();

        completion(nil);
    };
    
    
    BOOL needsBootstrap = ![[NSFileManager defaultManager] fileExistsAtPath:installedPath];
    if (needsBootstrap) {
        // First, wipe any existing content that's not basebin
        for (NSURL *subItemURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:JBROOT_PATH(@"/")] includingPropertiesForKeys:nil options:0 error:nil]) {
            if (![subItemURL.lastPathComponent isEqualToString:@"basebin"]) {
                [[NSFileManager defaultManager] removeItemAtURL:subItemURL error:nil];
            }
        }
        
        /*void (^bootstrapDownloadCompletion)(NSString *, NSError *) = ^(NSString *path, NSError *error) {
            if (error) {
                completion(error);
                return;
            }
            [self extractBootstrap:path withCompletion:bootstrapFinishedCompletion];
        };*/
        
        [[DOUIManager sharedInstance] sendLog:@"Extracting Bootstrap" debug:NO];

        NSString *bootstrapZstdPath = [NSString stringWithFormat:@"%@/bootstrap_%@.tar.zst", [NSBundle mainBundle].bundlePath, [self bootstrapVersion]];
        [self extractBootstrap:bootstrapZstdPath withCompletion:bootstrapFinishedCompletion];

        /*NSString *documentsCandidate = @"/var/mobile/Documents/bootstrap.tar.zstd";
        NSString *bundleCandidate = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"bootstrap.tar.zstd"];
        // Check if the user provided a bootstrap
        if ([[NSFileManager defaultManager] fileExistsAtPath:documentsCandidate]) {
            bootstrapDownloadCompletion(documentsCandidate, nil);
        }
        else if ([[NSFileManager defaultManager] fileExistsAtPath:bundleCandidate]) {
            bootstrapDownloadCompletion(bundleCandidate, nil);
        }
        else {
            [[DOUIManager sharedInstance] sendLog:@"Downloading Bootstrap" debug:NO];
            [self downloadBootstrapWithCompletion:bootstrapDownloadCompletion];
        }*/
    }
    else {
        bootstrapFinishedCompletion(nil);
    }
}
#endif

- (int)installPackage:(NSString *)packagePath
{
    if (getuid() == 0) {
        return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-i", packagePath.fileSystemRepresentation, NULL);
    }
    else {
        // idk why but waitpid sometimes fails and this returns -1, so we just ignore the return value
        exec_cmd(JBROOT_PATH("/basebin/jbctl"), "internal", "install_pkg", packagePath.fileSystemRepresentation, NULL);
        return 0;
    }
}

- (int)uninstallPackageWithIdentifier:(NSString *)identifier
{
    return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-r", identifier.UTF8String, NULL);
}

- (NSString *)installedVersionForPackageWithIdentifier:(NSString *)identifier
{
    NSString *dpkgStatus = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/var/lib/dpkg/status") encoding:NSUTF8StringEncoding error:nil];
    if (!dpkgStatus) return nil;

    NSArray *packageInfos = [dpkgStatus componentsSeparatedByString:@"\n\n"];
    for (NSString *packageInfo in packageInfos) {
        __block NSString *package = nil;
        __block NSString *status = nil;
        __block NSString *version = nil;
        [packageInfo enumerateLinesUsingBlock:^(NSString * _Nonnull line, BOOL * _Nonnull stop) {
            if ([line hasPrefix:@"Package: "]) package = [line substringFromIndex:9];
            else if ([line hasPrefix:@"Status: "]) status = [line substringFromIndex:8];
            else if ([line hasPrefix:@"Version: "]) version = [line substringFromIndex:9];
        }];
        if ([package isEqualToString:identifier] &&
            [status isEqualToString:@"install ok installed"]) {
            return version;
        }
    }
    return nil;
}

- (NSError *)installPackageManagers
{
    NSArray *enabledPackageManagers = [[DOUIManager sharedInstance] enabledPackageManagers];
    for (NSDictionary *packageManagerDict in enabledPackageManagers) {
        NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:packageManagerDict[@"Package"]];
        NSString *name = packageManagerDict[@"Display Name"];
        int r = [self installPackage:path];
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install %@: %d\n", name, r]}];
        }
    }
    return nil;
}

- (BOOL)shouldInstallPackage:(NSString *)identifier
{
    NSString *bundledVersion = gBundledPackages[identifier];
    if (!bundledVersion) return NO;
    
    NSString *installedVersion = [self installedVersionForPackageWithIdentifier:identifier];
    if (!installedVersion) return YES;

    // Package revisions can contain Debian suffixes such as "-13+opamine1".
    // Let dpkg compare them instead of truncating them into three numeric fields.
    int comparison = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"),
                                      "--compare-versions",
                                      installedVersion.fileSystemRepresentation,
                                      "lt",
                                      bundledVersion.fileSystemRepresentation,
                                      NULL);
    return comparison == 0;
}

#if 0
- (NSError *)finalizeBootstrap
{
    // Initial setup on first jailbreak
    if ([[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/prep_bootstrap.sh")]) {
        [[DOUIManager sharedInstance] sendLog:@"Finalizing Bootstrap" debug:NO];
        int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), JBROOT_PATH("/prep_bootstrap.sh"), NULL);
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"prep_bootstrap.sh returned %d\n", r]}];
        }
        
        NSError *error = [self installPackageManagers];
        if (error) return error;
    }
    
    BOOL shouldInstallLibroot = [self shouldInstallPackage:@"libroot-dopamine"];
    BOOL shouldInstallLibkrw = [self shouldInstallPackage:@"libkrw0-dopamine"];
    BOOL shouldInstallBasebinLink = [self shouldInstallPackage:@"dopamine-basebin-link"];
    
    if (shouldInstallLibroot || shouldInstallLibkrw || shouldInstallBasebinLink) {
        [[DOUIManager sharedInstance] sendLog:@"Updating Bundled Packages" debug:NO];
        if (shouldInstallLibroot) {
            NSString *librootPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libroot.deb"];
            int r = [self installPackage:librootPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install libroot: %d\n", r]}];
        }
        
        if (shouldInstallLibkrw) {
            NSString *libkrwPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libkrw-dopamine.deb"];
            int r = [self installPackage:libkrwPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install the libkrw plugin: %d\n", r]}];
        }
        
        if (shouldInstallBasebinLink) {
            // Clean symlinks from earlier Dopamine versions
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/opainject")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/opainject") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/jbctl")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/jbctl") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/lib/libjailbreak.dylib")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/lib/libjailbreak.dylib") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/libjailbreak.dylib")]) {
                // Yes this exists >.< was a typo
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/libjailbreak.dylib") error:nil];
            }
            
            NSString *basebinLinkPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin-link.deb"];
            int r = [self installPackage:basebinLinkPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install basebin link: %d\n", r]}];
        }
    }

    return nil;
}

- (NSError *)deleteBootstrap
{
    NSError *error = [self ensurePrivatePrebootIsWritable];
    if (error) return error;
    NSString *path = [[NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
    if (error) return error;
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:nil];
    return error;
}

- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)downloadTask didWriteData:(int64_t)bytesWritten totalBytesWritten:(int64_t)totalBytesWritten totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite
{
    if (downloadTask == _bootstrapDownloadTask) {
        NSString *sizeString = [NSByteCountFormatter stringFromByteCount:totalBytesWritten countStyle:NSByteCountFormatterCountStyleFile];
        NSString *writtenBytesString = [NSByteCountFormatter stringFromByteCount:totalBytesExpectedToWrite countStyle:NSByteCountFormatterCountStyleFile];
        
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Downloading Bootstrap (%@/%@)", sizeString, writtenBytesString] debug:NO update:YES];
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    _downloadCompletionBlock(nil, error);
}

- (void)URLSession:(nonnull NSURLSession *)session downloadTask:(nonnull NSURLSessionDownloadTask *)downloadTask didFinishDownloadingToURL:(nonnull NSURL *)location
{
    _downloadCompletionBlock(location, nil);
}
#endif

@end


/************************* roothide specific *******************/

////////////////////////
uint64_t jbrand_new();
uint64_t jbrand_current();
int is_jbroot_name(const char *name);
NSString* find_jbroot(BOOL force);
static void RootHideSetCachedJailbreakRoot(NSString *primaryPath);
////////////////////////////////////////
NSString* jbrootPrefix(NSString *path);
NSString* rootfsPrefix(NSString* path);
///////////////////////////////////////////////////////

uint64_t jbrand_new()
{
    uint64_t value = ((uint64_t)arc4random()) | ((uint64_t)arc4random())<<32;
    uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
    return (value & ~0xFF) | check;
}

int is_jbrand_value(uint64_t value)
{
   uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
   return check == (uint8_t)value;
}

#define JB_ROOT_PREFIX ".jbroot-"
#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)

static NSString * const RootHidePrimaryJailbreakRootDirectory = @"/var/containers/Bundle/Application";
static NSString * const RootHideSecondaryJailbreakRootDirectory = @"/var/mobile/Containers/Shared/AppGroup";
static NSString * const RootHideLegacyBundleIdentifier = @"com.opa334.Dopamine-roothide";

typedef NS_ENUM(NSUInteger, RootHideJailbreakRootState) {
    // The entry has the randomized-root spelling but makes no claim to be ours.
    RootHideJailbreakRootStateUnowned,
    // A foreign RootHide bootstrap, or an install marker tied to another app.
    RootHideJailbreakRootStateForeign,
    // An owned root whose paired-root links point somewhere unexpected.
    RootHideJailbreakRootStateInvalid,
    RootHideJailbreakRootStateRepairable,
    RootHideJailbreakRootStateReady,
};

typedef NS_ENUM(NSUInteger, RootHideLinkState) {
    RootHideLinkStateMissing,
    RootHideLinkStateExpected,
    RootHideLinkStateUnexpected,
};

static NSString *gRootHideCachedJailbreakRoot = nil;

static BOOL RootHidePathNodeExists(NSString *path)
{
    struct stat st = {0};
    return path.length > 0 && lstat(path.fileSystemRepresentation, &st) == 0;
}

static BOOL RootHideDirectoryExists(NSString *path)
{
    BOOL isDirectory = NO;
    return path.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDirectory] && isDirectory;
}

static BOOL RootHideRegularFileExists(NSString *path)
{
    struct stat st = {0};
    return path.length > 0 && lstat(path.fileSystemRepresentation, &st) == 0 && S_ISREG(st.st_mode);
}

static NSString *RootHideSecondaryJailbreakRootForPrimary(NSString *primaryPath)
{
    return [RootHideSecondaryJailbreakRootDirectory stringByAppendingPathComponent:primaryPath.lastPathComponent];
}

static RootHideLinkState RootHideLinkStateAtPath(NSString *path, NSString *expectedDestination)
{
    NSError *error = nil;
    NSString *destination = [[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:path error:&error];
    if (!destination) {
        return RootHidePathNodeExists(path) ? RootHideLinkStateUnexpected : RootHideLinkStateMissing;
    }
    return [destination isEqualToString:expectedDestination] ? RootHideLinkStateExpected : RootHideLinkStateUnexpected;
}

static BOOL RootHideOwnsBundleIdentifier(NSString *identifier)
{
    NSString *trimmedIdentifier = [identifier stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *currentIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if (trimmedIdentifier.length == 0) {
        return NO;
    }
    return [trimmedIdentifier isEqualToString:currentIdentifier] || [trimmedIdentifier isEqualToString:RootHideLegacyBundleIdentifier];
}

static RootHideJailbreakRootState RootHideJailbreakRootStateForPrimaryPath(NSString *primaryPath)
{
    NSFileManager *fileManager = NSFileManager.defaultManager;
    NSString *installMarker = [primaryPath stringByAppendingPathComponent:@".installed_dopamine"];
    NSString *foreignBootstrapMarker = [primaryPath stringByAppendingPathComponent:@".bootstrapped"];
    NSString *foreignTheBootstrapMarker = [primaryPath stringByAppendingPathComponent:@".thebootstrapped"];

    if ([fileManager fileExistsAtPath:foreignBootstrapMarker] || [fileManager fileExistsAtPath:foreignTheBootstrapMarker]) {
        return RootHideJailbreakRootStateForeign;
    }
    if (!RootHideRegularFileExists(installMarker)) {
        return RootHideJailbreakRootStateUnowned;
    }

    NSString *identityPath = [primaryPath stringByAppendingPathComponent:@"basebin/.AppIdentifier"];
    if (RootHidePathNodeExists(identityPath)) {
        if (!RootHideRegularFileExists(identityPath)) {
            return RootHideJailbreakRootStateInvalid;
        }
        NSString *storedIdentifier = [NSString stringWithContentsOfFile:identityPath encoding:NSUTF8StringEncoding error:nil];
        if (!RootHideOwnsBundleIdentifier(storedIdentifier)) {
            return RootHideJailbreakRootStateForeign;
        }
    }
    // Older RootHide installs did not persist an app identifier. The exact
    // paired-root contract below is required before treating that legacy marker
    // as ours, and the current identifier is written on the next update.

    NSString *secondaryPath = RootHideSecondaryJailbreakRootForPrimary(primaryPath);
    NSString *secondaryVarPath = [secondaryPath stringByAppendingPathComponent:@"var"];
    if (!RootHideDirectoryExists(primaryPath) || !RootHideDirectoryExists(secondaryPath) || !RootHideDirectoryExists(secondaryVarPath)) {
        return RootHideJailbreakRootStateInvalid;
    }

    RootHideLinkState primaryVarLink = RootHideLinkStateAtPath([primaryPath stringByAppendingPathComponent:@"var"], @"private/var");
    RootHideLinkState primaryPrivateVarLink = RootHideLinkStateAtPath([primaryPath stringByAppendingPathComponent:@"private/var"], secondaryVarPath);
    RootHideLinkState secondaryRootLink = RootHideLinkStateAtPath([secondaryPath stringByAppendingPathComponent:@".jbroot"], primaryPath);
    if (primaryVarLink == RootHideLinkStateUnexpected || primaryPrivateVarLink == RootHideLinkStateUnexpected || secondaryRootLink == RootHideLinkStateUnexpected) {
        return RootHideJailbreakRootStateInvalid;
    }
    if (primaryVarLink == RootHideLinkStateMissing || primaryPrivateVarLink == RootHideLinkStateMissing || secondaryRootLink == RootHideLinkStateMissing) {
        return RootHideJailbreakRootStateRepairable;
    }
    return RootHideJailbreakRootStateReady;
}

static NSError *RootHideRootError(NSString *description)
{
    return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : description}];
}

static NSString *RootHideFindOwnedJailbreakRoot(BOOL allowRepairable, NSError **errorOut)
{
    if (errorOut) {
        *errorOut = nil;
    }

    NSError *directoryError = nil;
    NSArray<NSString *> *subItems = [NSFileManager.defaultManager contentsOfDirectoryAtPath:RootHidePrimaryJailbreakRootDirectory error:&directoryError];
    if (!subItems) {
        if (errorOut) {
            *errorOut = directoryError ?: RootHideRootError(@"Unable to enumerate randomized RootHide roots.");
        }
        return nil;
    }
    NSString *selectedPath = nil;
    for (NSString *subItem in subItems) {
        if (!is_jbroot_name(subItem.UTF8String)) {
            continue;
        }

        NSString *candidatePath = [RootHidePrimaryJailbreakRootDirectory stringByAppendingPathComponent:subItem];
        RootHideJailbreakRootState state = RootHideJailbreakRootStateForPrimaryPath(candidatePath);
        if (state == RootHideJailbreakRootStateUnowned) {
            continue;
        }
        if (state == RootHideJailbreakRootStateForeign || state == RootHideJailbreakRootStateInvalid || (state == RootHideJailbreakRootStateRepairable && !allowRepairable)) {
            if (errorOut) {
                *errorOut = RootHideRootError([NSString stringWithFormat:@"Refusing to select randomized root %@ because its ownership or paired-root contract is invalid.", candidatePath]);
            }
            return nil;
        }
        if (selectedPath) {
            if (errorOut) {
                *errorOut = RootHideRootError(@"Multiple owned RootHide/Opamine randomized roots were found; refusing to select or modify either one.");
            }
            return nil;
        }
        selectedPath = candidatePath;
    }
    return selectedPath;
}

static BOOL RootHideRepairPairedRootLinks(NSString *primaryPath, NSError **errorOut)
{
    if (errorOut) {
        *errorOut = nil;
    }
    if (RootHideJailbreakRootStateForPrimaryPath(primaryPath) != RootHideJailbreakRootStateRepairable) {
        if (errorOut) {
            *errorOut = RootHideRootError(@"Refusing paired-root recovery because the root is not an unambiguous, repairable RootHide/Opamine install.");
        }
        return NO;
    }

    NSFileManager *fileManager = NSFileManager.defaultManager;
    NSString *secondaryPath = RootHideSecondaryJailbreakRootForPrimary(primaryPath);
    NSArray<NSDictionary<NSString *, NSString *> *> *links = @[
        @{ @"path" : [primaryPath stringByAppendingPathComponent:@"var"], @"destination" : @"private/var" },
        @{ @"path" : [primaryPath stringByAppendingPathComponent:@"private/var"], @"destination" : [secondaryPath stringByAppendingPathComponent:@"var"] },
        @{ @"path" : [secondaryPath stringByAppendingPathComponent:@".jbroot"], @"destination" : primaryPath },
    ];

    for (NSDictionary<NSString *, NSString *> *link in links) {
        NSString *path = link[@"path"];
        NSString *destination = link[@"destination"];
        RootHideLinkState state = RootHideLinkStateAtPath(path, destination);
        if (state == RootHideLinkStateUnexpected) {
            if (errorOut) {
                *errorOut = RootHideRootError([NSString stringWithFormat:@"Refusing paired-root recovery because %@ points somewhere unexpected.", path]);
            }
            return NO;
        }
        if (state == RootHideLinkStateMissing && ![fileManager createSymbolicLinkAtPath:path withDestinationPath:destination error:errorOut]) {
            return NO;
        }
    }

    if (RootHideJailbreakRootStateForPrimaryPath(primaryPath) != RootHideJailbreakRootStateReady) {
        if (errorOut) {
            *errorOut = RootHideRootError(@"Paired-root recovery did not restore the expected RootHide randomized-root contract.");
        }
        return NO;
    }
    return YES;
}

static BOOL RootHideReplaceExpectedSymlink(NSString *path, NSString *expectedDestination, NSString *replacementDestination, NSError **errorOut)
{
    if (RootHideLinkStateAtPath(path, expectedDestination) != RootHideLinkStateExpected) {
        if (errorOut) {
            *errorOut = RootHideRootError([NSString stringWithFormat:@"Refusing to replace unexpected randomized-root link %@.", path]);
        }
        return NO;
    }
    NSFileManager *fileManager = NSFileManager.defaultManager;
    NSString *temporaryPath = [path stringByAppendingFormat:@".opamine-link-%@", NSUUID.UUID.UUIDString];
    if (![fileManager createSymbolicLinkAtPath:temporaryPath withDestinationPath:replacementDestination error:errorOut]) {
        return NO;
    }
    if (rename(temporaryPath.fileSystemRepresentation, path.fileSystemRepresentation) != 0) {
        int renameError = errno;
        [fileManager removeItemAtPath:temporaryPath error:nil];
        if (errorOut) {
            *errorOut = [NSError errorWithDomain:NSPOSIXErrorDomain code:renameError userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed atomically replacing randomized-root link %@: %s", path, strerror(renameError)]}];
        }
        return NO;
    }
    return YES;
}

static NSString *RootHideDiscoverAndRecoverOwnedJailbreakRoot(NSError **errorOut)
{
    NSError *discoveryError = nil;
    NSString *primaryPath = RootHideFindOwnedJailbreakRoot(YES, &discoveryError);
    if (discoveryError) {
        if (errorOut) {
            *errorOut = discoveryError;
        }
        return nil;
    }
    if (!primaryPath || RootHideJailbreakRootStateForPrimaryPath(primaryPath) == RootHideJailbreakRootStateReady) {
        if (errorOut) {
            *errorOut = nil;
        }
        return primaryPath;
    }

    NSError *recoveryError = nil;
    if (!RootHideRepairPairedRootLinks(primaryPath, &recoveryError)) {
        if (errorOut) {
            *errorOut = recoveryError ?: RootHideRootError(@"RootHide paired-root recovery failed.");
        }
        return nil;
    }
    RootHideSetCachedJailbreakRoot(primaryPath);
    if (!find_jbroot(YES)) {
        if (errorOut) {
            *errorOut = RootHideRootError(@"Recovered RootHide root did not pass ownership validation.");
        }
        return nil;
    }
    if (errorOut) {
        *errorOut = nil;
    }
    return primaryPath;
}

static NSError *RootHideWriteCurrentAppIdentifier(NSString *primaryPath)
{
    NSString *identifier = NSBundle.mainBundle.bundleIdentifier;
    if (identifier.length == 0) {
        return RootHideRootError(@"Cannot persist an empty Opamine application identifier.");
    }
    NSString *identityPath = [primaryPath stringByAppendingPathComponent:@"basebin/.AppIdentifier"];
    if (![identifier writeToFile:identityPath atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        return RootHideRootError([NSString stringWithFormat:@"Failed to persist the Opamine application identifier at %@.", identityPath]);
    }
    return nil;
}

int is_jbroot_name(const char *name)
{
    if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp=NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if(!endp || *endp!='\0')
        return 0;
    
    if(!is_jbrand_value(value))
        return 0;
    
    return 1;
}

uint64_t resolve_jbrand_value(const char *name)
{
    if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp=NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if(!endp || *endp!='\0')
        return 0;
    
    if(!is_jbrand_value(value))
        return 0;
    
    return value;
}

NSString* find_jbroot(BOOL force)
{
    if(!force && gRootHideCachedJailbreakRoot) {
        return gRootHideCachedJailbreakRoot;
    }
    @synchronized(@"find_jbroot_lock")
    {
        // A randomized name and checksum are not ownership proof. Discovery
        // accepts exactly one complete, self-consistent RootHide/Opamine pair.
        // In-progress installs explicitly seed this cache with their newly
        // created path instead of broadening discovery to arbitrary roots.
        gRootHideCachedJailbreakRoot = RootHideFindOwnedJailbreakRoot(NO, nil);
    }
    return gRootHideCachedJailbreakRoot;
}

static void RootHideSetCachedJailbreakRoot(NSString *primaryPath)
{
    @synchronized(@"find_jbroot_lock")
    {
        gRootHideCachedJailbreakRoot = [primaryPath copy];
    }
}
////////////////////////////////////////////
uint64_t jbrand_current()
{
    NSString* jbroot = find_jbroot(NO);
    assert(jbroot != NULL);
    return resolve_jbrand_value([jbroot lastPathComponent].UTF8String);
}

NSString* jbrootPrefix(NSString *path)
{
    if(!path || path.UTF8String[0]!='/') {
        return path;
    }
    NSString* jbroot = find_jbroot(NO);
    assert(jbroot != NULL); //to avoid [nil stringByAppendingString:
    return [jbroot stringByAppendingPathComponent:path];
}

NSString* rootfsPrefix(NSString* path)
{
    if(!path || path.UTF8String[0]!='/') {
        return path;
    }
    return [@"/rootfs/" stringByAppendingPathComponent:path];
}
/////////////////////////////////////////////////////////////////////

#define DOPAMINE_INSTALL_VERSION    2

#define DEFAULT_SOURCES "\
Types: deb\n\
URIs: https://yourepo.com/\n\
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https://repo.chariz.com/\n\
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https://havoc.app/\n\
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: http://apt.thebigboss.org/repofiles/cydia/\n\
Suites: stable\n\
Components: main\n\
\n\
Types: deb\n\
URIs: https://roothide.github.io/\n\
Suites: ./\n\
Components:\n\
\n\
Types: deb\n\
URIs: https://roothide.github.io/procursus\n\
Suites: iphoneos-arm64e/%d\n\
Components: main\n\
\n\
Types: deb\n\
URIs: https://github.com/roothide/roothide.github.io/releases/download/%d/\n\
Suites: ./\n\
Components:\n\
"

// #define ALT_SOURCES "\
// Types: deb\n\
// URIs: https://iosjb.top/\n\
// Suites: ./\n\
// Components:\n\
// \n\
// Types: deb\n\
// URIs: https://iosjb.top/procursus\n\
// Suites: iphoneos-arm64e/%d\n\
// Components: main\n\
// "

#define ZEBRA_SOURCES "\
# Zebra Sources List\n\
deb https://getzbra.com/repo/ ./\n\
deb https://repo.chariz.com/ ./\n\
deb https://yourepo.com/ ./\n\
deb https://havoc.app/ ./\n\
deb https://roothide.github.io/ ./\n\
deb https://roothide.github.io/procursus iphoneos-arm64e/%d main\n\
deb https://github.com/roothide/roothide.github.io/releases/download/%d/ ./\n\
\n\
"

int getCFMajorVersion(void)
{
    if(@available(iOS 16.0, *)) {
        return 1900;
    }
    
    return ((int)kCFCoreFoundationVersionNumber / 100) * 100;
}
/////////////////////////////////////////////////////////////////////

@implementation DOBootstrapper(roothide)

#define STRAPLOG(...)   [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@__VA_ARGS__] debug:YES];
#define ASSERT(...)     do{if(!(__VA_ARGS__)) {completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"ABORT: %s (%d): %s", __FILE_NAME__, __LINE__, #__VA_ARGS__]}]);return -1;}} while(0)
#define ROOT_HIDE_INSTALL_ASSERT(...) do{if(!(__VA_ARGS__)) {RootHideSetCachedJailbreakRoot(nil); completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"ABORT: %s (%d): %s", __FILE_NAME__, __LINE__, #__VA_ARGS__]}]);return -1;}} while(0)

- (NSString *)bootstrapVersion
{
    return [NSString stringWithFormat:@"%d", getCFMajorVersion()];
}

-(int) buildPackageSources:(void (^)(NSError *))completion
{
    NSFileManager* fm = NSFileManager.defaultManager;
    
    ASSERT([[NSString stringWithFormat:@(DEFAULT_SOURCES), getCFMajorVersion(), getCFMajorVersion()] writeToFile:jbrootPrefix(@"/etc/apt/sources.list.d/default.sources") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    
    // //Users in some regions seem to be unable to access github.io
    // if([NSLocale.currentLocale.countryCode isEqualToString:@"CN"]) {
    //     ASSERT([[NSString stringWithFormat:@(ALT_SOURCES), getCFMajorVersion()] writeToFile:jbrootPrefix(@"/etc/apt/sources.list.d/sileo.sources") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    // }
    
    if(![fm fileExistsAtPath:jbrootPrefix(@"/var/mobile/Library/Application Support/xyz.willy.Zebra")])
    {
        NSDictionary* attr = @{NSFilePosixPermissions:@(0755), NSFileOwnerAccountID:@(501), NSFileGroupOwnerAccountID:@(501)};
        ASSERT([fm createDirectoryAtPath:jbrootPrefix(@"/var/mobile/Library/Application Support/xyz.willy.Zebra") withIntermediateDirectories:YES attributes:attr error:nil]);
    }
    
    ASSERT([[NSString stringWithFormat:@(ZEBRA_SOURCES), getCFMajorVersion(), getCFMajorVersion()] writeToFile:jbrootPrefix(@"/var/mobile/Library/Application Support/xyz.willy.Zebra/sources.list") atomically:YES encoding:NSUTF8StringEncoding error:nil]);
    
    return 0;
}

-(int) InstallBootstrap:(NSString*)installPath WithCompletion:(void (^)(NSError *))completion
{
    [[DOUIManager sharedInstance] sendLog:@"Extracting Bootstrap" debug:NO];

    NSFileManager* fm = NSFileManager.defaultManager;
    
    NSString* jbroot_path = installPath;
    RootHideSetCachedJailbreakRoot(nil);
    
    ASSERT(mkdir(jbroot_path.fileSystemRepresentation, 0755) == 0);
    ASSERT(chown(jbroot_path.fileSystemRepresentation, 0, 0) == 0);
    
    NSString* bootstrapZstFile = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:
                                  [NSString stringWithFormat:@"bootstrap_%d.tar.zst", getCFMajorVersion()]];

    ROOT_HIDE_INSTALL_ASSERT([fm fileExistsAtPath:bootstrapZstFile]);
    
    NSString* bootstrapTarFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"bootstrap.tar"];
    if([fm fileExistsAtPath:bootstrapTarFile])
        ROOT_HIDE_INSTALL_ASSERT([fm removeItemAtPath:bootstrapTarFile error:nil]);
    
    NSError* error = [self decompressZstd:bootstrapZstFile toTar:bootstrapTarFile];
    if(error) {
        RootHideSetCachedJailbreakRoot(nil);
        completion(error);
        return -1;
    }
    
    NSError* decompressionError = [self extractTar:bootstrapTarFile toPath:jbroot_path];
    if (decompressionError) {
        RootHideSetCachedJailbreakRoot(nil);
        completion(decompressionError);
        return -1;
    }

    // The newly extracted root is not finalized and deliberately has no
    // ownership marker yet. Only now, after extraction succeeded, may this
    // invocation seed the cache for its own paired-root setup.
    RootHideSetCachedJailbreakRoot(jbroot_path);

    // jbrootPrefix() and jbrand_current() are available for this known path.
    
    NSString* jbroot_secondary = [NSString stringWithFormat:@"/var/mobile/Containers/Shared/AppGroup/.jbroot-%016llX", jbrand_current()];
    ROOT_HIDE_INSTALL_ASSERT(mkdir(jbroot_secondary.fileSystemRepresentation, 0755) == 0);
    ROOT_HIDE_INSTALL_ASSERT(chown(jbroot_secondary.fileSystemRepresentation, 0, 0) == 0);
    
    ROOT_HIDE_INSTALL_ASSERT([fm moveItemAtPath:jbrootPrefix(@"/var") toPath:[jbroot_secondary stringByAppendingPathComponent:@"/var"] error:nil]);
    ROOT_HIDE_INSTALL_ASSERT([fm createSymbolicLinkAtPath:jbrootPrefix(@"/var") withDestinationPath:@"private/var" error:nil]);
    
    ROOT_HIDE_INSTALL_ASSERT([fm removeItemAtPath:jbrootPrefix(@"/private/var") error:nil]);
    ROOT_HIDE_INSTALL_ASSERT([fm createSymbolicLinkAtPath:jbrootPrefix(@"/private/var") withDestinationPath:[jbroot_secondary stringByAppendingPathComponent:@"/var"] error:nil]);
    
    ROOT_HIDE_INSTALL_ASSERT([fm removeItemAtPath:[jbroot_secondary stringByAppendingPathComponent:@"/var/tmp"] error:nil]);
    ROOT_HIDE_INSTALL_ASSERT([fm moveItemAtPath:jbrootPrefix(@"/tmp") toPath:[jbroot_secondary stringByAppendingPathComponent:@"/var/tmp"] error:nil]);
    ROOT_HIDE_INSTALL_ASSERT([fm createSymbolicLinkAtPath:jbrootPrefix(@"/tmp") withDestinationPath:@"var/tmp" error:nil]);
    
    ROOT_HIDE_INSTALL_ASSERT([fm createSymbolicLinkAtPath:[jbroot_secondary stringByAppendingPathComponent:@".jbroot"]
                    withDestinationPath:jbroot_path error:nil]);

    if(![fm fileExistsAtPath:jbrootPrefix(@"/var/mobile/Library/Preferences")])
    {
        NSDictionary* attr = @{NSFilePosixPermissions:@(0755), NSFileOwnerAccountID:@(501), NSFileGroupOwnerAccountID:@(501)};
        ROOT_HIDE_INSTALL_ASSERT([fm createDirectoryAtPath:jbrootPrefix(@"/var/mobile/Library/Preferences") withIntermediateDirectories:YES attributes:attr error:nil]);
    }
    
    if([self buildPackageSources:completion] != 0) {
        RootHideSetCachedJailbreakRoot(nil);
        return -1;
    }
    
    STRAPLOG("Status: Bootstrap Installed");
    
    return 0;
}

-(int) ReRandomizeBootstrap:(void (^)(NSError *))completion
{
    [[DOUIManager sharedInstance] sendLog:@"ReRandomizing Bootstrap" debug:NO];

    NSString *oldPrimaryPath = find_jbroot(NO);
    if (!oldPrimaryPath || RootHideJailbreakRootStateForPrimaryPath(oldPrimaryPath) != RootHideJailbreakRootStateReady) {
        completion(RootHideRootError(@"Refusing to re-randomize an invalid RootHide randomized-root pair."));
        return -1;
    }
    NSString *oldSecondaryPath = RootHideSecondaryJailbreakRootForPrimary(oldPrimaryPath);
    NSString *newPrimaryPath = nil;
    NSString *newSecondaryPath = nil;
    for (NSUInteger attempt = 0; attempt < 16; attempt++) {
        NSString *candidateName = [NSString stringWithFormat:@".jbroot-%016llX", jbrand_new()];
        NSString *primaryCandidate = [RootHidePrimaryJailbreakRootDirectory stringByAppendingPathComponent:candidateName];
        NSString *secondaryCandidate = [RootHideSecondaryJailbreakRootDirectory stringByAppendingPathComponent:candidateName];
        if (!RootHidePathNodeExists(primaryCandidate) && !RootHidePathNodeExists(secondaryCandidate)) {
            newPrimaryPath = primaryCandidate;
            newSecondaryPath = secondaryCandidate;
            break;
        }
    }
    if (!newPrimaryPath) {
        completion(RootHideRootError(@"Could not allocate an unused RootHide randomized-root name for re-randomization."));
        return -1;
    }

    NSFileManager *fileManager = NSFileManager.defaultManager;
    NSError *operationError = nil;
    BOOL movedPrimary = NO;
    BOOL movedSecondary = NO;
    BOOL rewrotePrimaryPrivateVar = NO;
    BOOL rewroteSecondaryRoot = NO;

    if (![fileManager moveItemAtPath:oldPrimaryPath toPath:newPrimaryPath error:&operationError]) {
        completion(operationError);
        return -1;
    }
    movedPrimary = YES;

    if (![fileManager moveItemAtPath:oldSecondaryPath toPath:newSecondaryPath error:&operationError]) {
        goto rollback;
    }
    movedSecondary = YES;

    if (!RootHideReplaceExpectedSymlink([newPrimaryPath stringByAppendingPathComponent:@"private/var"],
                                        [oldSecondaryPath stringByAppendingPathComponent:@"var"],
                                        [newSecondaryPath stringByAppendingPathComponent:@"var"],
                                        &operationError)) {
        goto rollback;
    }
    rewrotePrimaryPrivateVar = YES;

    if (!RootHideReplaceExpectedSymlink([newSecondaryPath stringByAppendingPathComponent:@".jbroot"], oldPrimaryPath, newPrimaryPath, &operationError)) {
        goto rollback;
    }
    rewroteSecondaryRoot = YES;

    RootHideSetCachedJailbreakRoot(newPrimaryPath);
    if (!find_jbroot(YES)) {
        operationError = RootHideRootError(@"Re-randomized RootHide root failed paired-root validation.");
        goto rollback;
    }

    // jbrootPrefix() and jbrand_current() are available again.
    return 0;

rollback:
    // Restore the old link destinations before moving either root back. Every
    // replacement is guarded by its expected destination, so rollback cannot
    // overwrite a path that changed outside this transaction.
    if (rewroteSecondaryRoot) {
        NSError *rollbackLinkError = nil;
        if (!RootHideReplaceExpectedSymlink([newSecondaryPath stringByAppendingPathComponent:@".jbroot"], newPrimaryPath, oldPrimaryPath, &rollbackLinkError) && !operationError) {
            operationError = rollbackLinkError;
        }
    }
    if (rewrotePrimaryPrivateVar) {
        NSError *rollbackLinkError = nil;
        if (!RootHideReplaceExpectedSymlink([newPrimaryPath stringByAppendingPathComponent:@"private/var"],
                                            [newSecondaryPath stringByAppendingPathComponent:@"var"],
                                            [oldSecondaryPath stringByAppendingPathComponent:@"var"],
                                            &rollbackLinkError) && !operationError) {
            operationError = rollbackLinkError;
        }
    }
    if (movedSecondary) {
        NSError *rollbackMoveError = nil;
        if (![fileManager moveItemAtPath:newSecondaryPath toPath:oldSecondaryPath error:&rollbackMoveError] && !operationError) {
            operationError = rollbackMoveError;
        }
    }
    if (movedPrimary) {
        NSError *rollbackMoveError = nil;
        if (![fileManager moveItemAtPath:newPrimaryPath toPath:oldPrimaryPath error:&rollbackMoveError] && !operationError) {
            operationError = rollbackMoveError;
        }
    }
    RootHideSetCachedJailbreakRoot(oldPrimaryPath);
    if (!find_jbroot(YES) || RootHideJailbreakRootStateForPrimaryPath(oldPrimaryPath) != RootHideJailbreakRootStateReady) {
        completion(RootHideRootError(@"RootHide re-randomization failed and rollback could not restore a valid randomized-root pair."));
        return -1;
    }
    completion(operationError ?: RootHideRootError(@"RootHide re-randomization failed; the original randomized-root pair was restored."));
    return -1;
}

-(int) doBootstrap:(void (^)(NSError *))completion {
    NSError *rootDiscoveryError = nil;
    NSString *jbroot_path = RootHideDiscoverAndRecoverOwnedJailbreakRoot(&rootDiscoveryError);
    if (rootDiscoveryError) {
        completion(rootDiscoveryError);
        return -1;
    }
    
    if(!jbroot_path) {
        STRAPLOG("device is not strapped...");

        for (NSUInteger attempt = 0; attempt < 16; attempt++) {
            NSString *candidateName = [NSString stringWithFormat:@".jbroot-%016llX", jbrand_new()];
            NSString *primaryCandidate = [RootHidePrimaryJailbreakRootDirectory stringByAppendingPathComponent:candidateName];
            NSString *secondaryCandidate = [RootHideSecondaryJailbreakRootDirectory stringByAppendingPathComponent:candidateName];
            if (!RootHidePathNodeExists(primaryCandidate) && !RootHidePathNodeExists(secondaryCandidate)) {
                jbroot_path = primaryCandidate;
                break;
            }
        }
        if (!jbroot_path) {
            completion(RootHideRootError(@"Could not allocate an unused randomized RootHide root name."));
            return -1;
        }
        
        STRAPLOG("bootstrap @ %@", jbroot_path);
        
        if([self InstallBootstrap:jbroot_path WithCompletion:completion] != 0) {
            return -1;
        }
        
    } else {
        STRAPLOG("device is strapped: %@", jbroot_path);
        
        STRAPLOG("Status: Rerandomize jbroot");
        
        if([self ReRandomizeBootstrap:completion] != 0) {
            return -1;
        }
    }
    
    STRAPLOG("Status: Bootstrap Successful");

    return 0;
}

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion
{

    // Remove /var/jb as it might be wrong
    NSError *error=nil;
    if (![self deleteSymlinkAtPath:@"/var/jb" error:&error]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
            if (![[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:&error]) {
                completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb directory failed with error: %@", error]}]);
                return;
            }
        }
        else {
            completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb symlink failed with error: %@", error]}]);
            return;
        }
    }
    
    // Clean up xinaA15 v1 leftovers if desired
        NSArray *xinaLeftoverSymlinks = @[
            @"/var/alternatives",
            @"/var/ap",
            @"/var/apt",
            @"/var/bin",
            @"/var/bzip2",
            @"/var/cache",
            @"/var/dpkg",
            @"/var/etc",
            @"/var/gzip",
            @"/var/lib",
            @"/var/Lib",
            @"/var/libexec",
            @"/var/Library",
            @"/var/LIY",
            @"/var/Liy",
            @"/var/local",
            @"/var/newuser",
            @"/var/profile",
            @"/var/sbin",
            @"/var/suid_profile",
            @"/var/sh",
            @"/var/sy",
            @"/var/share",
            @"/var/ssh",
            @"/var/sudo_logsrvd.conf",
            @"/var/suid_profile",
            @"/var/sy",
            @"/var/usr",
            @"/var/zlogin",
            @"/var/zlogout",
            @"/var/zprofile",
            @"/var/zshenv",
            @"/var/zshrc",
            @"/var/log/dpkg",
            @"/var/log/apt",
        ];
        NSArray *xinaLeftoverFiles = @[
            @"/var/lib",
            @"/var/master.passwd",
            @"/var/.keep_symlinks",
        ];
        
        for (NSString *xinaLeftoverSymlink in xinaLeftoverSymlinks) {
            [self deleteSymlinkAtPath:xinaLeftoverSymlink error:nil];
        }
        
        for (NSString *xinaLeftoverFile in xinaLeftoverFiles) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:xinaLeftoverFile]) {
                [[NSFileManager defaultManager] removeItemAtPath:xinaLeftoverFile error:nil];
            }
        }
    
    if([self doBootstrap:completion] == 0) {
        
        //update jailbreakInfo.rootPath and jailbreakInfo.jbrand
        [[DOEnvironmentManager sharedManager] locateJailbreakRoot];
        
        [[DOUIManager sharedInstance] sendLog:@"Updating BaseBin" debug:NO];
        
        NSError* error=nil;
        if ([[NSFileManager defaultManager] fileExistsAtPath:jbrootPrefix(@"/basebin")]) {
            if (![[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/basebin") error:&error]) {
                completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed deleting existing basebin file with error: %@", error.localizedDescription]}]);
                return;
            }
        }
        error = [self extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:jbrootPrefix(@"/")];
        if (error) {
            completion(error);
            return;
        }
        NSString *basebinMD5Path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.md5"];
        NSString *installedBasebinMD5Path = jbrootPrefix(@"/basebin/.basebin_md5");
        if ([[NSFileManager defaultManager] fileExistsAtPath:basebinMD5Path]) {
            [[NSFileManager defaultManager] removeItemAtPath:installedBasebinMD5Path error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:basebinMD5Path toPath:installedBasebinMD5Path error:nil];
        }
        [self patchBasebinDaemonPlists];
        [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/basebin/basebin.tc") error:nil];

        NSError *identityError = RootHideWriteCurrentAppIdentifier(jbrootPrefix(@"/"));
        if (identityError) {
            completion(identityError);
            return;
        }
        
        JBFixMobilePermissions();
        
        completion(nil);
    }
}

-(int) fixBootstrapSymlink:(NSString*)path
{
    const char* jbpath = jbrootPrefix(path).fileSystemRepresentation;
    
    struct stat st={0};
    int r = lstat(jbpath, &st);
    if(r != 0) {
        assert(errno != 0);
        return errno;
    }
    
    if (!S_ISLNK(st.st_mode)) {
        return 0;
    }
    
    char link[PATH_MAX+1] = {0};
    assert(readlink(jbpath, link, sizeof(link)-1) > 0);
    if(link[0] != '/') {
        return 0;
    }

    //stringByStandardizingPath won't remove /private/ prefix if the path does not exist on disk
    NSString* _link = @(link).stringByStandardizingPath.stringByResolvingSymlinksInPath;
    
    NSString *pattern = @"^(?:/private)?/var/containers/Bundle/Application/\\.jbroot-[0-9A-Z]{16}(/.+)$";
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
    NSTextCheckingResult *match = [regex firstMatchInString:_link options:0 range:NSMakeRange(0, [_link length])];
    assert(match != nil);
    
    NSString* target = [_link substringWithRange:[match rangeAtIndex:1]];
    NSString* newlink = [@".jbroot" stringByAppendingPathComponent:target];
    
    assert(unlink(jbpath) == 0);
    assert(symlink(newlink.fileSystemRepresentation, jbpath) == 0);
    assert(access(jbpath, F_OK) == 0);
    
    return 0;
}

- (NSError *)finalizeBootstrap
{
    // Initial setup on first jailbreak
    if ([[NSFileManager defaultManager] fileExistsAtPath:jbrootPrefix(@"/prep_bootstrap.sh")]) {
        [[DOUIManager sharedInstance] sendLog:@"Finalizing Bootstrap" debug:NO];
        int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), "/prep_bootstrap.sh", NULL);
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"prep_bootstrap.sh returned %d\n", r]}];
        }
        
        NSError *error = [self installPackageManagers];
        if (error) return error;
        
        NSString *roothideManager = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"roothideapp.deb"];
         r = [self installPackage:roothideManager];
        if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install roothideManager: %d\n", r]}];

        //Remove the shits triggered by uicache before first jailbreak is fully activated.
        [NSFileManager.defaultManager removeItemAtPath:@"/var/mobile/Library/SplashBoard/Snapshots/xyz.willy.Zebra" error:nil];
        [NSFileManager.defaultManager removeItemAtPath:@"/var/mobile/Library/SplashBoard/Snapshots/com.roothide.manager" error:nil];
        [NSFileManager.defaultManager removeItemAtPath:@"/var/mobile/Library/SplashBoard/Snapshots/org.coolstar.SileoStore" error:nil];
    }
    else
    {
        [[DOUIManager sharedInstance] sendLog:@"Updating Symlinks" debug:NO];

        NSArray* bootstrapSymlinks = @[@"/bin/sh", @"/usr/bin/sh"];
        for(NSString* slink in bootstrapSymlinks)
        {
            int r = [self fixBootstrapSymlink:slink];
            if(r != 0) {
                return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"fixBootstrapSymlink(%@) returned %d\n", slink, r]}];
            }
        }
        
        int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), "/usr/libexec/updatelinks.sh", NULL);
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"updatelinks.sh returned %d\n", r]}];
        }
    }
    
    BOOL shouldInstallLibkrw = [self shouldInstallPackage:@"libkrw0-dopamine"];
    BOOL shouldInstallBasebinLink = [self shouldInstallPackage:@"dopamine-basebin-link"];
    BOOL shouldInstallRoothideCore = [self shouldInstallPackage:@"roothide"];
    // Respect the package-manager choice: update Sileo only when it is already installed.
    BOOL sileoInstalled = [self installedVersionForPackageWithIdentifier:@"org.coolstar.sileo"] != nil;
    BOOL shouldInstallSileo = sileoInstalled && [self shouldInstallPackage:@"org.coolstar.sileo"];
    
    if (shouldInstallLibkrw || shouldInstallBasebinLink || shouldInstallRoothideCore || shouldInstallSileo) {
        [[DOUIManager sharedInstance] sendLog:@"Updating Bundled Packages" debug:NO];

        if (shouldInstallRoothideCore) {
            NSString *roothideCorePath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"roothide.deb"];
            int r = [self installPackage:roothideCorePath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install RootHide Core: %d\n", r]}];
        }

        if (shouldInstallSileo) {
            NSString *sileoPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"sileo.deb"];
            int r = [self installPackage:sileoPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install the hardened Sileo package: %d\n", r]}];
        }
        
        if (shouldInstallLibkrw) {
            NSString *libkrwPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libkrw-dopamine.deb"];
            int r = [self installPackage:libkrwPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install the libkrw plugin: %d\n", r]}];
        }
        
        if (shouldInstallBasebinLink) {
            // Clean symlinks from earlier Dopamine versions
            if ([self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/bin/opainject")]) {
                [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/bin/opainject") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/bin/jbctl")]) {
                [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/bin/jbctl") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/lib/libjailbreak.dylib")]) {
                [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/lib/libjailbreak.dylib") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/bin/libjailbreak.dylib")]) {
                // Yes this exists >.< was a typo
                [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/bin/libjailbreak.dylib") error:nil];
            }

            NSString *basebinLinkPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin-link.deb"];
            int r = [self installPackage:basebinLinkPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install basebin link: %d\n", r]}];
        }
    }


    if ([self fileOrSymlinkExistsAtPath:jbrootPrefix(@"/usr/lib/libroot.dylib")]) {
        [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/usr/lib/libroot.dylib") error:nil];
    }
    NSString *librootPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libroot.deb"];
    NSString* unpackedPath = [NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    int ret = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg-deb"), "-R", rootfsPrefix(librootPath).fileSystemRepresentation, rootfsPrefix(unpackedPath).fileSystemRepresentation, NULL);
    if (ret != 0) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to unpack deb: %d\n", ret]}];
    }
    NSError* error=nil;
    [[NSFileManager defaultManager] copyItemAtPath:[unpackedPath stringByAppendingPathComponent:@"/var/jb/usr/lib/libroot.dylib"] toPath:jbrootPrefix(@"/usr/lib/libroot.dylib") error:&error];
    if(error) {
        return error;
    }
    if(![[NSFileManager defaultManager] removeItemAtPath:unpackedPath error:&error]) {
        return error;
    }

    
    [[NSString stringWithFormat:@"%d",DOPAMINE_INSTALL_VERSION] writeToFile:jbrootPrefix(@"/.installed_dopamine") atomically:YES encoding:NSUTF8StringEncoding error:nil];
    
    if(jbclient_palehide_present()) {
        [@"" writeToFile:jbrootPrefix(@"/.installed_palera1n") atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } else {
        [[NSFileManager defaultManager] removeItemAtPath:jbrootPrefix(@"/.installed_palera1n") error:nil];
    }

    return nil;
}

- (NSError *)deleteBootstrap
{
    // Never remove a directory just because it has a valid randomized-root
    // spelling. Select exactly one owned pair, then remove only that pair.
    NSError *discoveryError = nil;
    NSString *primaryPath = RootHideFindOwnedJailbreakRoot(YES, &discoveryError);
    if (discoveryError) {
        return discoveryError;
    }
    if (!primaryPath) {
        return nil;
    }
    if (RootHideJailbreakRootStateForPrimaryPath(primaryPath) == RootHideJailbreakRootStateRepairable) {
        return RootHideRootError(@"Refusing to remove an owned RootHide root until its paired-root links are recovered and verified.");
    }
    if (RootHideJailbreakRootStateForPrimaryPath(primaryPath) != RootHideJailbreakRootStateReady) {
        return RootHideRootError(@"Refusing to remove a RootHide root whose ownership contract is invalid.");
    }

    NSFileManager *fileManager = NSFileManager.defaultManager;
    NSString *secondaryPath = RootHideSecondaryJailbreakRootForPrimary(primaryPath);
    NSError *error = nil;
    STRAPLOG("remove owned RootHide pair %@ and %@", primaryPath, secondaryPath);
    if (![fileManager removeItemAtPath:primaryPath error:&error]) {
        return error;
    }
    if (![fileManager removeItemAtPath:secondaryPath error:&error]) {
        return error;
    }
    RootHideSetCachedJailbreakRoot(nil);
    return nil;
}

@end

/////////////////////////////////////////////////////////////////

@implementation DOEnvironmentManager(roothide)
- (void)locateJailbreakRoot
{
    if(gSystemInfo.jailbreakInfo.rootPath) {
        free(gSystemInfo.jailbreakInfo.rootPath);
        gSystemInfo.jailbreakInfo.rootPath = NULL;
    }
    
    // A brand-new bootstrap is deliberately not marked installed until
    // finalization. Its path is cached only by InstallBootstrap; normal process
    // startup has no cache and therefore still requires complete ownership.
    NSString *jbroot_path = find_jbroot(NO) ?: find_jbroot(YES);
    if(jbroot_path) {
        gSystemInfo.jailbreakInfo.rootPath = strdup(jbroot_path.fileSystemRepresentation);
        gSystemInfo.jailbreakInfo.jbrand = jbrand_current();
    }
}
- (NSError *)ensureJailbreakRootExists
{
    return nil;
}
@end

/************************************** roothide specific *******************************************/

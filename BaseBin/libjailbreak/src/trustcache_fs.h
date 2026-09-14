#ifndef TRUSTCACHE_FS_H
#define TRUSTCACHE_FS_H

#include <stdbool.h>

/* These helpers intentionally route each regular file through RootHide's
 * path-aware collector.  They therefore retain the Cryptex, removable-app,
 * TrollStore Lite, and jbrand-randomized-cdhash policy instead of bulk
 * trusting a directory with raw upstream hashes. */
int jb_trustcache_add_file(const char *filePath);
int jb_trustcache_add_directory(const char *directoryPath, bool recursive);

#endif

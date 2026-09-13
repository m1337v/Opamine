#include <stdbool.h>

int envbuf_len(const char *envp[]);
char **envbuf_mutcopy(const char *envp[]);
void envbuf_free(char *envp[]);
int envbuf_find(const char * const envp[], const char *name);
const char *envbuf_getenv(const char * const envp[], const char *name);

/*
 * These mutators leave *envpp unchanged on failure.  Callers that alter a
 * process handoff must check every required mutation before using the copy.
 */
bool envbuf_setenv(char **envpp[], const char *name, const char *value);
bool envbuf_unsetenv(char **envpp[], const char *name);

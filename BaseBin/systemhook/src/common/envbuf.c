#include "envbuf.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

int envbuf_len(const char *envp[])
{
	if (envp == NULL) return 1;

	int k = 0;
	const char *env = envp[k++];
	while (env != NULL) {
		env = envp[k++];
	}
	return k;
}

char **envbuf_mutcopy(const char *envp[])
{
	if (envp == NULL) return NULL;

	int len = envbuf_len(envp);
	if (len <= 0 || (size_t)len > SIZE_MAX / sizeof(char *)) return NULL;
	char **envcopy = calloc((size_t)len, sizeof(*envcopy));
	if (!envcopy) return NULL;

	for (int i = 0; i < len-1; i++) {
		envcopy[i] = strdup(envp[i]);
		if (!envcopy[i]) {
			envbuf_free(envcopy);
			return NULL;
		}
	}

	return envcopy;
}

void envbuf_free(char *envp[])
{
	if (envp == NULL) return;

	int len = envbuf_len((const char**)envp);
	for (int i = 0; i < len-1; i++) {
		free(envp[i]);
	}
	free(envp);
}

int envbuf_find(const char * const envp[], const char *name)
{
	if (envp && name && name[0]) {
		unsigned long nameLen = strlen(name);
		int k = 0;
		const char *env = envp[k++];
		while (env != NULL) {
			unsigned long envLen = strlen(env);
			if (envLen > nameLen) {
				if (!strncmp(env, name, nameLen)) {
					if (env[nameLen] == '=') {
						return k-1;
					}
				}
			}
			env = envp[k++];
		}
	}
	return -1;
}

const char *envbuf_getenv(const char * const envp[], const char *name)
{
	if (envp) {
		unsigned long nameLen = strlen(name);
		int envIndex = envbuf_find(envp, name);
		if (envIndex >= 0) {
			return &envp[envIndex][nameLen+1];
		}
	}
	return NULL;
}

bool envbuf_setenv(char **envpp[], const char *name, const char *value)
{
	if (!envpp || !name || !name[0] || !value) {
		return false;
	}

	char **envp = *envpp;
	bool created_empty_buffer = false;
	if (!envp) {
		// Treat NULL as [NULL], but publish it only after all allocation works.
		envp = calloc(1, sizeof(*envp));
		if (!envp) return false;
		created_empty_buffer = true;
	}

	size_t name_len = strlen(name);
	size_t value_len = strlen(value);
	if (name_len > SIZE_MAX - value_len - 2) {
		if (created_empty_buffer) free(envp);
		return false;
	}
	char *envToSet = malloc(name_len + value_len + 2);
	if (!envToSet) {
		if (created_empty_buffer) free(envp);
		return false;
	}
	memcpy(envToSet, name, name_len);
	envToSet[name_len] = '=';
	memcpy(envToSet + name_len + 1, value, value_len + 1);

	int existingEnvIndex = envbuf_find((const char **)envp, name);
	if (existingEnvIndex >= 0) {
		// The new allocation exists before the old value is released.
		free(envp[existingEnvIndex]);
		envp[existingEnvIndex] = envToSet;
		if (created_empty_buffer) *envpp = envp;
		return true;
	}

	// If it doesn't exist yet, grow before publishing either the new value or
	// (for a NULL input) the newly-created empty environment.
	int prevLen = envbuf_len((const char **)envp);
	if (prevLen <= 0 || (size_t)prevLen > (SIZE_MAX / sizeof(*envp)) - 1) {
		free(envToSet);
		if (created_empty_buffer) free(envp);
		return false;
	}
	char **resized = realloc(envp, (size_t)(prevLen + 1) * sizeof(*envp));
	if (!resized) {
		free(envToSet);
		if (created_empty_buffer) free(envp);
		return false;
	}
	resized[prevLen-1] = envToSet;
	resized[prevLen] = NULL;
	*envpp = resized;
	return true;
}

bool envbuf_unsetenv(char **envpp[], const char *name)
{
	if (!envpp || !name || !name[0]) {
		return false;
	}
	char **envp = *envpp;
	if (!envp) return true;

	int existingEnvIndex = envbuf_find((const char **)envp, name);
	if (existingEnvIndex < 0) return true;

	free(envp[existingEnvIndex]);
	int prevLen = envbuf_len((const char **)envp);
	for (int i = existingEnvIndex; i < (prevLen-1); i++) {
		envp[i] = envp[i+1];
	}
	/* Keep the existing allocation. Shrinking is only an optimization, while a
	 * failed realloc would otherwise make ownership ambiguous after removal. */
	return true;
}

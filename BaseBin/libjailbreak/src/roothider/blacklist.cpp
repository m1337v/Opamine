#include <map>
#include <set>
#include <bsm/audit.h>
#include <pthread.h>
#include <dispatch/dispatch.h>

extern "C"
{

#include <libproc.h>
#include <sys/proc_info.h>

#include "../libjailbreak.h"
#include "common.h"

extern int audit_token_to_pidversion(audit_token_t atoken);

}

//do not use cxx auto constructors

enum
{
    kBlacklistedProcessStatePlain = 1,
    kBlacklistedProcessStateRestrictedAllowlist = 2,
};

typedef struct {
    int pidversion;
    int state;
} BlacklistedProcessState;

static std::map<pid_t*, int>* uncachedBlacklistedProcesses;
static std::map<pid_t, BlacklistedProcessState>* blacklistedProcessesState;

static void cxx_global_vars_init()
{
    uncachedBlacklistedProcesses = new std::map<pid_t*, int>();
    blacklistedProcessesState = new std::map<pid_t, BlacklistedProcessState>();
}

static pthread_rwlock_t stateLock = {0};

static void stateLockInit()
{
    pthread_rwlock_init(&stateLock, NULL);
}
static void stateReadLock()
{
    pthread_rwlock_rdlock(&stateLock);
}
static void stateReadUnlock()
{
    pthread_rwlock_unlock(&stateLock);
}
static void stateWriteLock()
{
    pthread_rwlock_wrlock(&stateLock);
}
static void stateWriteUnlock()
{
    pthread_rwlock_unlock(&stateLock);
}

static void initBlacklistState()
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        stateLockInit();
        cxx_global_vars_init();
    });
}

static int _blacklistedProcessState(pid_t pid, int pidversion)
{
    initBlacklistState();

    int blacklistedState = 0;

    stateReadLock();

    for (auto it = uncachedBlacklistedProcesses->begin(); it != uncachedBlacklistedProcesses->end(); ++it)
    {
        pid_t uncachedPid = *(it->first);
        if(uncachedPid>0 && uncachedPid==pid)
        {
            if(pidversion==proc_get_pidversion(uncachedPid)) {
                blacklistedState = it->second;
            }
            break;
        }
    }

    if(blacklistedState == 0)
    {
        auto it = blacklistedProcessesState->find(pid);
        if(it != blacklistedProcessesState->end())
        {
            BlacklistedProcessState cachedState = it->second;
            if(cachedState.pidversion == pidversion)
            {
                blacklistedState = cachedState.state;
            }
        }        
    }
    
    stateReadUnlock();

    return blacklistedState;
}

extern "C" bool isBlacklistedToken(audit_token_t* token)
{
    pid_t pid = audit_token_to_pid(*token);
    int pidversion = audit_token_to_pidversion(*token);
    return _blacklistedProcessState(pid, pidversion) != 0;
}

extern "C" bool isBlacklistedPid(pid_t pid)
{
    return _blacklistedProcessState(pid, proc_get_pidversion(pid)) != 0;
}

extern "C" bool isRestrictedBlacklistedToken(audit_token_t* token)
{
    pid_t pid = audit_token_to_pid(*token);
    int pidversion = audit_token_to_pidversion(*token);
    return _blacklistedProcessState(pid, pidversion) == kBlacklistedProcessStateRestrictedAllowlist;
}

extern "C" bool isRestrictedBlacklistedPid(pid_t pid)
{
    return _blacklistedProcessState(pid, proc_get_pidversion(pid)) == kBlacklistedProcessStateRestrictedAllowlist;
}

static pid_t* _allocBlacklistProcessIdWithState(int state)
{
    initBlacklistState();

    pid_t* pidp = (pid_t*)malloc(sizeof(pid_t));

    *pidp = 0;

    stateWriteLock();

    (*uncachedBlacklistedProcesses)[pidp] = state;
    
    stateWriteUnlock();

    return pidp;
}

extern "C" pid_t* allocBlacklistProcessId(void)
{
    return _allocBlacklistProcessIdWithState(kBlacklistedProcessStatePlain);
}

extern "C" pid_t* allocRestrictedBlacklistedProcessId(void)
{
    return _allocBlacklistProcessIdWithState(kBlacklistedProcessStateRestrictedAllowlist);
}

extern "C" void commitBlacklistProcessId(pid_t* pidp)
{
    initBlacklistState();

    stateWriteLock();

    int state = kBlacklistedProcessStatePlain;
    auto uncachedIt = uncachedBlacklistedProcesses->find(pidp);
    if (uncachedIt != uncachedBlacklistedProcesses->end()) {
        state = uncachedIt->second;
    }

    pid_t pid = *pidp;
    if(pid > 0)
    {
        int pidversion = proc_get_pidversion(pid);
        if (pidversion > 0) {
            (*blacklistedProcessesState)[pid] = { pidversion, state };
        }
    }

    uncachedBlacklistedProcesses->erase(pidp);

    free(pidp);

    stateWriteUnlock();
}

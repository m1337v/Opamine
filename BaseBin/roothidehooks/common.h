
#include <stdbool.h>


bool isJailbreakPath(const char* path);

bool isNormalAppPath(const char* path);

bool isSandboxedApp(pid_t pid, const char* path);

int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

bool isBlacklisted(const char* path);
BOOL isBlacklistedApp(NSString* identifier);

/* csops  operations */
#define	CS_OPS_STATUS		0	/* return status */
#define CS_PLATFORM_BINARY          0x04000000  /* this is a platform binary */
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

//These apps may be signed with a (fake) certificate
#define SENSITIVE_APP_LIST   @[ \
    @"com.icraze.gtatracker", \
    @"com.Alfie.TrollInstallerX", \
    @"com.opa334.Dopamine", \
    @"com.opa334.Dopamine.roothide", \
    @"com.opa334.Dopamine-roothide", \
    @"com.opa334.TrollStore", \
    @"com.netskao.dumpdecrypter", \
    @"com.fiore.trolldecrypt", \
    @"wiki.qaq.TrollFools", \
    @"com.AppInstalleriOS.TrollSign", \
    @"Liliana.Violyn", \
    @"com.apple.terminal", \
    @"com.tigisoftware.filza", \
    @"com.m1337.Filzer", \
    @"com.creaturecoding.tweaksettings", \
    @"com.mika.LocationSimulation", \
    @"com.liguangming.Shadowrocket", \
    @"com.m1337.varCleanRH", \
    @"com.82flex.reveil", \
    @"com.resonance.store", \
    @"com.m1337.store", \
    @"dev.mineek.muffinstore", \
    @"org.coolstar.SileoStore", \
    @"xyz.willy.Zebra", \
    @"com.roothide.patcher", \
    @"com.roothide.manager", \
    @"com.opa334.CraneApplication", \
    @"com.ichitaso.powerselectorapp", \
    @"com.sgwc.Ghost", \
    @"com.sgwc.Orbit", \
    @"com.sgwc.Capture", \
    @"com.cokepokes.AppStorePlus", \
    @"com.kahsooa.piqwkk.dummy", \
]

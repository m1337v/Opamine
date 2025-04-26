
#include <stdbool.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/codesign.h>

bool isJailbreakBundlePath(const char* path);

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

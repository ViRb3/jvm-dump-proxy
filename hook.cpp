#include <Windows.h>
#include "mhook/mhook-lib/mhook.h"
#include "jni.h"
#include "proxy.h"
#include "dump.h"

using namespace std;

typedef jclass JNICALL (*sig_JVM_DefineClass)(JNIEnv *env, const char *name, jobject loader,
                                              const jbyte *buf, jsize len, jobject pd);
typedef jclass JNICALL(*sig_JVM_DefineClassWithSource)(JNIEnv *env, const char *name, jobject loader, const jbyte *buf,
                                                       jsize len, jobject pd, const char *source);
typedef jclass JNICALL (*sig_JVM_DefineClassWithSourceCond)(JNIEnv *env, const char *name,
                                                            jobject loader, const jbyte *buf, jsize len, jobject pd,
                                                            const char *source, jboolean verify);

sig_JVM_DefineClass orig_JVM_DefineClass = NULL;
sig_JVM_DefineClassWithSource orig_JVM_DefineClassWithSource = NULL;
sig_JVM_DefineClassWithSourceCond orig_JVM_DefineClassWithSourceCond = NULL;

jclass JNICALL detour_JVM_DefineClass(JNIEnv *env, const char *name, jobject loader,
                                      const jbyte *buf, jsize len, jobject pd) {
    DoDump((char *) buf, len);
    return orig_JVM_DefineClass(env, name, loader, buf, len, pd);
}

jclass JNICALL detour_JVM_DefineClassWithSource(JNIEnv *env, const char *name, jobject loader, const jbyte *buf,
                                                jsize len, jobject pd, const char *source) {
    DoDump((char *) buf, len);
    return orig_JVM_DefineClassWithSource(env, name, loader, buf, len, pd, source);
}

jclass JNICALL detour_JVM_DefineClassWithSourceCond(JNIEnv *env, const char *name, jobject loader, const jbyte *buf,
                                                    jsize len, jobject pd, const char *source, jboolean verify) {
    DoDump((char *) buf, len);
    return orig_JVM_DefineClassWithSourceCond(env, name, loader, buf, len, pd, source, verify);
}

bool doHook() {
    HMODULE hJvm = LoadLibrary("jvm.dll");
    if (!hJvm) {
        return FALSE;
    }
    orig_JVM_DefineClass = (sig_JVM_DefineClass) GetProcAddress(hJvm, "JVM_DefineClass");
    if (!orig_JVM_DefineClass) {
        return FALSE;
    }
    orig_JVM_DefineClassWithSource = (sig_JVM_DefineClassWithSource) GetProcAddress(hJvm, "JVM_DefineClassWithSource");
    if (!orig_JVM_DefineClassWithSource) {
        return FALSE;
    }
    orig_JVM_DefineClassWithSourceCond = (sig_JVM_DefineClassWithSourceCond) GetProcAddress(hJvm,
                                                                                            "JVM_DefineClassWithSourceCond");
    if (!orig_JVM_DefineClassWithSourceCond) {
        return FALSE;
    }

    HOOK_INFO hooks[] = {{(PVOID *) &orig_JVM_DefineClass,               (PVOID) detour_JVM_DefineClass},
                         {(PVOID *) &orig_JVM_DefineClassWithSource,     (PVOID) detour_JVM_DefineClassWithSource},
                         {(PVOID *) &orig_JVM_DefineClassWithSourceCond, (PVOID) detour_JVM_DefineClassWithSourceCond}};
    return Mhook_SetHookEx(hooks, 3) == 3;
}

bool WINAPI DllMain(HMODULE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        SourceInit();
        if (doHook()) {
            MessageBox(NULL, "Hooks initialized.", "Success", MB_OK);
        } else {
            MessageBox(NULL, "Something went wrong.", "Error", MB_OK);
        }
    }
    return TRUE;
}
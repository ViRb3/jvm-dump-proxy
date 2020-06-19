#ifndef VERSION_DUMP_H
#define VERSION_DUMP_H

#include <Windows.h>
#include <Shlobj.h>
#include <string>
#include <mutex>
#include "parser.h"

using namespace std;

mutex dumpMutex;

bool fileExists(const wstring &name) {
    if (FILE *file = _wfopen(name.c_str(), L"r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }
}

bool getNextFreeFilePath(wstring &path, const char *name) {
    path.resize(MAX_PATH);
    if (!SHGetSpecialFolderPathW(HWND_DESKTOP, path.data(), CSIDL_DESKTOP, FALSE)) {
        return false;
    }
    path.resize(wcslen(path.data()));

    wstring fixedName(MAX_PATH, '\x00');
    mbstowcs(fixedName.data(), name, strlen(name));
    PathCleanupSpec(nullptr, fixedName.data());
    fixedName.resize(wcslen(fixedName.data()));

    int initialLen = path.length();
    int i = 0;
    do {
        path.resize(initialLen);
        path += L"\\JVMDUMP\\";
        path += fixedName;
        if (i != 0) {
            path += to_wstring(i);
        }
        path += L".class";
        i++;
    } while (fileExists(path));
    return true;
}

void DoDump(const char *buf, int len) {
    if (!buf || len < 1) {
        return;
    }
    lock_guard<mutex> lock(dumpMutex);
    FILE *fp;
    wstring path;
    string className = GetJavaClassName(buf);
    if (getNextFreeFilePath(path, className.c_str())) {
        fp = _wfopen(path.c_str(), L"wb");
        int written = fwrite(buf, sizeof(char), len, fp);
        if (written == 0) {
            MessageBox(nullptr, "Error 2", "Error", MB_OK);
        } else if (written != sizeof(char) * len) {
            MessageBox(nullptr, "Error 3", "Error", MB_OK);
        }
        fclose(fp);
    } else {
        MessageBox(nullptr, "Error 1", "Error", MB_OK);
    }
}

#endif //VERSION_DUMP_H

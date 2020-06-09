#ifndef VERSION_DUMP_H
#define VERSION_DUMP_H

#include <Windows.h>
#include <Shlobj.h>
#include <string>
#include <mutex>
#include "parser.h"

using namespace std;

mutex _mutex;

BOOL FileExists(const wstring &name) {
    if (FILE *file = _wfopen(name.c_str(), L"r")) {
        fclose(file);
        return TRUE;
    } else {
        return FALSE;
    }
}

BOOL GetNextFreeFilePath(wstring &path, const char *name) {
    path.resize(MAX_PATH);
    if (!SHGetSpecialFolderPathW(HWND_DESKTOP, path.data(), CSIDL_DESKTOP, FALSE)) {
        return FALSE;
    }
    path.resize(wcslen(path.data()));

    wstring fixedName(MAX_PATH, '\x00');
    mbstowcs(fixedName.data(), name, strlen(name));
    PathCleanupSpec(NULL, fixedName.data());
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
    } while (FileExists(path));
    return TRUE;
}

void DoDump(const char *buf, int len) {
    if (!buf || len < 1) {
        return;
    }
    unique_lock<mutex> lock(_mutex);
    FILE *fp;
    wstring path;
    string className = GetJavaClassName(buf);
    if (GetNextFreeFilePath(path, className.c_str())) {
        fp = _wfopen(path.c_str(), L"wb");
        int written = fwrite(buf, sizeof(char), len, fp);
        if (written == 0) {
            MessageBox(NULL, "Error 2", "Error", MB_OK);
        } else if (written != sizeof(char) * len) {
            MessageBox(NULL, "Error 3", "Error", MB_OK);
        }
        fclose(fp);
    } else {
        MessageBox(NULL, "Error 1", "Error", MB_OK);
    }
    lock.unlock();
}

#endif //VERSION_DUMP_H

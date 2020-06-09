# Mhook - a Windows API hooking library [![Build status](https://ci.appveyor.com/api/projects/status/qieg4d47uqv00we0/branch/master?svg=true)](https://ci.appveyor.com/project/apriorit/mhook/branch/master)

- [Introduction](#introduction)
- [How to use](#how-to-use)
- [License](#license)
- [Version history](#version-history)
- [Acknowledgements](#acknowledgements)

# Introduction
This library was created as a free alternative to [Microsoft Detours](http://research.microsoft.com/sn/detours). It is originally developed by Marton Anka and currently is supported and developed by [Apriorit](https://www.apriorit.com/).

# How to use
```C++
// Include a header
#include <mhook-lib/mhook.h>

// Save the original function
typedef ULONG (WINAPI* _NtClose)(IN HANDLE Handle);
_NtClose TrueNtClose = (_NtClose)GetProcAddress(GetModuleHandle(L"ntdll"), "NtClose");

// Declare your function that will be handle a hook:
ULONG WINAPI HookNtClose(HANDLE hHandle) 
{
    printf("***** Call to NtClose(0x%p)\n", hHandle);
    return TrueNtClose(hHandle);
}

//...

// Set the hook 
BOOL isHookSet = Mhook_SetHook((PVOID*)&TrueNtClose, HookNtClose);

//...

// After finishing using the hook – remove it
Mhook_Unhook((PVOID*)&TrueNtClose);

```

You can also set a bunch of hooks in one call:
```C++
HOOK_INFO hooks[] =
{
    { (PVOID*)&TrueNtOpenProcess, HookNtOpenProcess },
    { (PVOID*)&TrueSelectObject, HookSelectobject },
    { (PVOID*)&Truegetaddrinfo, Hookgetaddrinfo },
    { (PVOID*)&TrueHeapAlloc, HookHeapAlloc },
    { (PVOID*)&TrueNtClose, HookNtClose }
};

int numberOfSetHooks = Mhook_SetHookEx(hooks, 5);
    
//...

// Removing hooks
int numberOfRemovedHooks = Mhook_UnhookEx(hooks, 5);
```

That way of setting multiple hooks is also much better in performance.

# License
Mhook is freely distributed under an [MIT license](https://choosealicense.com/licenses/mit/).

# Version history

## Version 2.5.1 (30 March 2018)
- Fix #1: VirtualAlloc hooking reports anomaly
- New #2: Add integration to vcpkg package
- New #3: Add AppVeyor CI 
- Fix #4: Add ability to hook functions with call in first 5 bytes

## Version 2.5 (20 Oct 2017)
- 10x performance boost
- CMake build system
- Change tabs to spaces
- Ability to hook functions with `je`/`jne` in the first 5 bytes
- Fix hook recursion
- Other fixes

## Version 2.4 (05 Mar 2014, the last from the original author)
- A number of improvements: hot patch location (mov edi, edi) handling, support for REX-prefixed EIP-relative jumps on x64, removal of compile-time limit on the number of hooks

## Version 2.3 (15 Jan 2012)
- A bugfix that allows hooking more API functions

## Version 2.2 (27 Jun 2008)
- Support for instructions using IP-relative addressing

## Version 2.1 (15 Oct 2007)
- Fixes

## Version 2.0 (08 Jul 2007)
- Built-in disassembler

## Version 1.0 (24 Jun 2007)
- Original release

# Acknowledgements
Mhook contains a disassembler that is a stripped-down version of the excellent tDisasm package by Matt Conover. Thank you Matt! tDisasm comes with a BSD-style license and re-releasig a derivative of it under the MIT license has been confirmed to be OK by its author. 

Alexandr Filenkov submitted bugfixes in Sept-2007. Michael Syrovatsky submitted fixes for IP-relative addressing in Jun-2008. Andrey Kubyshev submitted a bugfix in Jul-2011 and Jan-2013. John McDonald enabled unlimited hooks. Kasper Brandt provided a fix for hot patch function prologues. 

# JVM Dump Proxy
> A proxy DLL for Windows to dump JVM classes at JNI level.

## Introduction
Some Java programs use [reflection](https://www.oracle.com/technical-resources/articles/java/javareflection.html) to hide their code by loading and executing classes dynamically. To tackle this, you could [dump them from memory](https://github.com/hengyunabc/dumpclass), or edit `rt.jar` and place a hook on various reflection methods. But sometimes authors will go a step further - they will unload classes after they have executed, preventing them from being dumped. And other times, crazy people will even use the native methods directly, bypassing any bytecode-level hooks.

This project aims to be a universal solution to all your dumping needs. By hooking at the lowest reliably accessible JNI level, it will dump all classes as they are being loaded.

## Limitations
- x64-only
- Only hooks `DefineClass*`. It is possible to bypass this method by implementing your own class loader [in JNI](https://stackoverflow.com/questions/3735233/encrypted-class-files-with-decryption-handled-by-a-native-library).

## Usage
Download the release and extract `version.dll`. Place it in your Java `bin` directory, next to `java.exe`. You may want to use a separate Java installation so you don't affect all processes. On your desktop, create a new directory called `JVMDUMP`.

When you run any program with the modified Java installation, you will see a message box with the hooking result. Once you press `Ok`, all loaded classes will be saved on your desktop under the directory on your desktop.

## FAQ
- Q: I am getting `Error 2` \
A: `JVMDUMP` is not accessible on your desktop
- Q: But duplicate classes? \
A: They will be appended with a number, nothing will be overwritten

## Technical details
### proxy.h, library.def
A simple proxy DLL implementation to inject into the JVM painlessly and reliably. For more information, check the [References](#References).
### hook.cpp
Installs the hooks that redirect methods to our code. Powered by [mhook](https://github.com/apriorit/mhook).
### dump.h
The class dumping logic.
### parser.h
A fast and simple Java class parser. It will parse the class name of each hooked byte buffer and use it to save the file under the appropriate name.

## Compilation
- mingw-w64 7.0.0+
- CMake 3.16+

## References
- If you would like to learn more about the proxy DLL technique, check out the base project [PerfectProxyDLL](https://github.com/ViRb3/PerfectProxyDLL).
- Control flow of [findClass](https://stackoverflow.com/questions/3544614/how-is-the-control-flow-to-findclass-of).
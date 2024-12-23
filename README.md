# HiJack
A tool that uses Windows mechanics to intercept process creation by adding a debugger to the registry.

# Commands
```
HiJack.exe /add <Filename>
HiJack.exe /remove <Filename>
```

# Usage
For example, we have `hello.exe`, which needs to be intercepted, to do this, we need to execute:
```
HiJack.exe /add hello.exe
```
After this, HiJack will intercept the process and inject into it the library `<filename>_hijack.dll` (`hello_hijack.dll`), which is located in the same directory as `hello.exe`.

# NOTE
For 32-bit processes you need to use 32-bit HiJack. Same for 64-bit.

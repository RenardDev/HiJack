# HiJack
A utility leveraging Windows mechanisms to intercept process creation by registering a debugger in the system registry.

# Commands
```
HiJack.exe /list
HiJack.exe /add <File Name>
HiJack.exe /remove <File Name>
```

# Usage
To intercept a process, such as hello.exe, execute the following command:
```
HiJack.exe /add hello.exe
```
This will enable HiJack to intercept the process creation of `hello.exe` and inject the library `<File Name>_hijack.dll` (e.g., `hello_hijack.dll` or `hello_hijack32.dll` if the process is 32-bit). The DLL must be located in the same directory as the intercepted executable.

# NOTE
* Ensure that you use the appropriate version of HiJack:
  - Use the 32-bit version for 32-bit processes.
  - Use the 64-bit version for 64-bit processes.
* The 32-bit version of HiJack can utilize the 64-bit version if both executables are placed in the same directory.
* The 64-bit version of HiJack can utilize the 32-bit version if both executables are placed in the same directory.
* The NTDLL project is a DLL that can be used as an example for injection.

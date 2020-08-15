# SassyKitdi

See writeup at https://zerosum0x0.blogspot.com/2020/08/sassykitdi-kernel-mode-tcp-sockets.html

## Build/Run

Install gcc-mingw-w64 and Rustup with x86_64-windows-pc-gnu target.

In src/payloads/sassykitdi there is build.sh and pyit.sh to build the project and scrape the shellcode out of the DLL.

## Exploit Preambles

SassyKitdi must be performed at PASSIVE_LEVEL. To use the sample project in an exploit payload, you will need to provide your own exploit preamble. This is the unique part of the exploit that cleans up the stack frame, and in e.g. EternalBlue lowers the IRQL from DISPATCH_LEVEL.


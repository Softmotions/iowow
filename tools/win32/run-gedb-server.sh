#!/bin/bash
# GDB: /usr/bin/x86_64-w64-mingw32-gdb
wine /usr/share/win64/gdbserver.exe --once :6667 $@



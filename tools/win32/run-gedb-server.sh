#!/bin/bash
# GDB: /usr/bin/x86_64-w64-mingw32-gdb
# apt-get install gdb-mingw-w64
wine64-development /usr/share/win64/gdbserver.exe --once :6667 $@



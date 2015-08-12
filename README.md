# 

IOWOW - C99 file IO library and buffer pool implementation
==========================================================

This library provides
--------------------

* Basic file IO routines (iwfile.h)
* Management of a file memory mmapped regions 
  and automatic file space expansion/truncation (iwexfile.h)
* Read/write locking of file address space within a threads (iwrwlfile.h)  
* Allocation/deallocation of data blocks within a file like `malloc` do for memory (iwfsmfile.h)
* Simple message logging facility (iwlog.h) 

Usage 
-----

Before using of any of provided modules you have to initialize this library by 
calling `iw_init()`:

    iwrc rc = iw_init();



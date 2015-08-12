# 

IOWOW - The C99 file IO library and free space management engine
================================================================

* Basic file IO routines (iwfile.h)
* Management of a file memory mmapped regions 
* Automatic file space expansion/truncation (iwexfile.h)
* Reader/writer locking of file address space among a threads (iwrwlfile.h)  
* Allocation/deallocation of data blocks within a file like `malloc` do for memory (iwfsmfile.h)
* Simple message logging facility (iwlog.h) 


Free space management within a single file (iwfsmfile.h)
--------------------------------------------------------

A file address space divided in blocks of fixed length where 
every block has its allocation status. The methods
`IWFS_FSM::allocate` and `IWFS_FSM::deallocate` behave like `malloc` and `free` 
memory management functions but within a file address space. 

A memory allocation status of all data blocks stored in the `bitmap` section. 
The hybrid combination of `bitmap` space and in-memory `B-Tree` index used to 
efficiently handle blocks allocations and deallocations.

Readers/writers locking over a file address space (iwrwlfile.h)
---------------------------------------------------------------

This part of library allows you to acquire reader/writer locks over a file 
address space within a threads. See ` IWFS_RWL`, `IWFS_RWL::lock`, `IWFS_RWL::unlock`.


Building
========

Currently only unix systems supported, windows port will be released soon. 

    cd ./iowow
    mkdir ./build && cd ./build
    cmake -DCMAKE_BUILD_TYPE=Debug|Release -DBUILD_TESTS:BOOL=ON .. 
    make
    
**Note** 

Before using of any of provided modules you have to initialize this library by 
calling `iw_init()`:

    iwrc rc = iw_init();



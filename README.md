IOWOW - The C11 persistent key/value database engine based on [skip list](https://en.wikipedia.org/wiki/Skip_list)
==================================================================================================================

# Key components

* [iwkv.h](https://github.com/Softmotions/iowow/blob/master/src/kv/iwkv.h) Persistent key/value database engine
* [iwfsmfile.h](https://github.com/Softmotions/iowow/blob/master/src/fs/iwfsmfile.h) File blocks allocation manager like `malloc()` on files

# IWKV

## Features

* Support of multiple key-value databases within a single file.
* Native support of integer keys
* Support of record values represented as sorted array of integers
* Ultra-fast traversal of database records
* Good performance comparing its main competitors: `lmdb`, `leveldb`, `kyoto cabinet`
* Simple C11 library can be easily embedded into any software

## Limitations

* Maximum iwkv storage file size: `255 GB (0x3fffffffc0)`
* Total size of a single key+value record must be not greater than 255Mb (0xfffffff)
* In-memory cache for every opened database takes ~130Kb, cache can be disposed by `iwkv_db_cache_release()`

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
* Tiny C11 library (150Kb) can be easily embedded into any software

## Limitations

* Maximum iwkv storage file size: `255 GB (0x3fffffffc0)`
* Total size of a single key+value record must be not greater than `255Mb (0xfffffff)`
* In-memory cache for every opened database takes `~130Kb`, cache can be disposed by `iwkv_db_cache_release()`

# Supported platforms

## Linux
### Ubuntu/Debian
#### PPA repository

```sh
sudo add-apt-repository ppa:adamansky/iwowo
sudo apt-get update
sudo apt-get install iowow
```

#### Building debian packages

```sh
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DPACKAGE_DEB=ON
make package
```

### RPM based Linux distributions
```sh
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DPACKAGE_RPM=ON
make package
```

## FreeBSD

Successfully tested on FreeBSD 10/11

## OSX

Successfully tested on OSX 10.12/10.13

## Windows

[Port pending](https://github.com/Softmotions/iowow/issues/1)





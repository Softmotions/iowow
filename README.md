IOWOW - The C11 persistent key/value database engine based on [skip list](https://en.wikipedia.org/wiki/Skip_list)
==================================================================================================================

Website http://iowow.io

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
sudo add-apt-repository ppa:adamansky/iwowow
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


# Example

```c
#include <iowow/iwkv.h>
#include <string.h>
#include <stdlib.h>

int main() {
  IWKV_OPTS opts = {
    .path = "example1.db",
    .oflags = IWKV_TRUNC // Cleanup database before open
  };
  IWKV iwkv;
  IWDB mydb;
  iwrc rc = iwkv_open(&opts, &iwkv);
  if (rc) {
    iwlog_ecode_error3(rc);
    return 1;
  }
  // Now open mydb
  // - Database id: 1
  rc = iwkv_db(iwkv, 1, 0, &mydb);
  if (rc) {
    iwlog_ecode_error2(rc, "Failed to open mydb");
    return 1;
  }
  // Work with db: put/get value
  IWKV_val key, val;
  key.data = "foo";
  key.size = strlen(key.data);
  val.data = "bar";
  val.size = strlen(val.data);

  fprintf(stdout, "put: %.*s => %.*s\n",
          (int) key.size, (char *) key.data,
          (int) val.size, (char *) val.data);

  rc = iwkv_put(mydb, &key, &val, 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    return rc;
  }
  // Retrive value associated with `foo` key
  val.data = 0;
  val.size = 0;
  rc = iwkv_get(mydb, &key, &val);
  if (rc) {
    iwlog_ecode_error3(rc);
    return rc;
  }

  fprintf(stdout, "get: %.*s => %.*s\n",
          (int) key.size, (char *) key.data,
          (int) val.size, (char *) val.data);

  iwkv_val_dispose(&val);
  iwkv_close(&iwkv);
  return 0;
}
```
**Compile and run:**

```sh
gcc -std=gnu11 -Wall -pedantic -c -o example1.o example1.c
gcc -o example1 example1.o -liowow

./example1
  put: foo => bar
  get: foo => bar
```




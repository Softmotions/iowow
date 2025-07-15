IOWOW — `C11` utility library and persistent key/value storage engine
==================================================================================================================

**NOTE: Issues tracker is disabled. You are welcome to contribute, pull requests accepted.**

[![license](https://img.shields.io/github/license/Softmotions/ejdb.svg)](https://github.com/Softmotions/iowow/blob/master/LICENSE)
![Maintained](https://img.shields.io/maintenance/yes/2025.svg)

Website https://iowow.softmotions.com

# Key components

* [utils](https://github.com/Softmotions/iowow/tree/master/src/utils) Useful data structures and various commonly used routines.
* [json](https://github.com/Softmotions/iowow/tree/master/src/json) JSON parsing and manipulation routines incluing JSON Patch/Pointers support.
* [iwkv.h](https://github.com/Softmotions/iowow/blob/master/src/kv/iwkv.h) Persistent key/value database engine.
* [iwfsmfile.h](https://github.com/Softmotions/iowow/blob/master/src/fs/iwfsmfile.h) File blocks allocation manager like `malloc()` on files.

## IWKV Features

* Support of multiple key-value databases within a single file
* Online database backups
* Native support of integer keys
* Write Ahead Logging (WAL)
* Ultra-fast traversal of database records
* Compound keys support
* Good performance comparing its main competitors: `lmdb`, `leveldb`, `kyoto cabinet`
* Tiny C11 library (200Kb) can be easily embedded into any software

## IWKV Limitations

* Maximum iwkv storage file size: `512 GB (0x7fffffff80)`
* Total size of a single key+value record must be not greater than `255Mb (0xfffffff)`

# Build

```sh
./build.sh
```

## Install

```sh
./build.sh --prefix=$HOME/.local
```

# Examples

[src/kv/examples](https://github.com/Softmotions/iowow/tree/master/src/kv/examples)

## Store and retrieve records

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
  // Retrieve value associated with `foo` key
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

## Cursor iteration example

```c
///
/// Fills database with a set of football table records
/// then traverse records according to club name in ascending and descending orders.
///

#include "iwkv.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static struct data_s {
  const char *club;
  uint8_t     points;
} _points[] = {

  { "Aston Villa",              25  },
  { "Manchester City",          57  },
  { "Arsenal",                  40  },
  { "Everton",                  37  },
  { "West Ham United",          27  },
  { "Tottenham Hotspur",        41  },
  { "Wolverhampton Wanderers",  43  },
  { "Norwich City",             21  },
  { "Leicester City",           53  },
  { "Manchester United",        45  },
  { "Newcastle United",         35  },
  { "Brighton & Hove Albion",   29  },
  { "AFC Bournemouth",          27  },
  { "Crystal Palace",           39  },
  { "Sheffield United",         43  },
  { "Burnley",                  39  },
  { "Southampton",              34  },
  { "Watford",                  27  },
  { "Chelsea",                  48  },
  { "Liverpool",                82  },
};

static iwrc run(void) {
  IWKV_OPTS opts = {
    .path = "cursor1.db",
    .oflags = IWKV_TRUNC // Cleanup database before open
  };
  IWKV iwkv;
  IWDB db;
  IWKV_cursor cur = 0;
  iwrc rc = iwkv_open(&opts, &iwkv);
  RCRET(rc);

  rc = iwkv_db(iwkv, 1, 0, &db);
  RCGO(rc, finish);

  for (int i = 0; i < sizeof(_points) / sizeof(_points[0]); ++i) {
    struct data_s *n = &_points[i];
    IWKV_val key = { .data = (void *) n->club, .size = strlen(n->club) };
    IWKV_val val = { .data = &n->points, .size = sizeof(n->points) };
    RCC(rc, finish, iwkv_put(db, &key, &val, 0));
  }

  fprintf(stdout, ">>>> Traverse in descending order\n");
  RCC(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0));
  while ((rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT)) == 0) {
    IWKV_val key, val;
    RCC(rc, finish, iwkv_cursor_get(cur, &key, &val));
    fprintf(stdout, "%.*s: %u\n",
            (int) key.size, (char *) key.data,
            *(uint8_t *) val.data);
    iwkv_kv_dispose(&key, &val);
  }
  rc = 0;
  iwkv_cursor_close(&cur);

  fprintf(stdout, "\n>>>> Traverse in ascending order\n");
  RCC(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_AFTER_LAST, 0));
  while ((rc = iwkv_cursor_to(cur, IWKV_CURSOR_PREV)) == 0) {
    IWKV_val key, val;
    RCC(rc, finish, iwkv_cursor_get(cur, &key, &val));
    fprintf(stdout, "%.*s: %u\n",
            (int) key.size, (char *) key.data,
            *(uint8_t *) val.data);
    iwkv_kv_dispose(&key, &val);
  }
  rc = 0;
  iwkv_cursor_close(&cur);

  // Select all keys greater or equal than: Manchester United
  {
    fprintf(stdout, "\n>>>> Records GE: %s\n", _points[9].club);
    IWKV_val key = { .data = (void *) _points[9].club, .size = strlen(_points[9].club) }, val;
    RCC(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_GE, &key));
    do {
      RCC(rc, finish, iwkv_cursor_get(cur, &key, &val));
      fprintf(stdout, "%.*s: %u\n",
              (int) key.size, (char *) key.data,
              *(uint8_t *) val.data);
      iwkv_kv_dispose(&key, &val);
    } while ((rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT)) == 0);
    rc = 0;
  }
  iwkv_cursor_close(&cur);

finish:
  if (cur) {
    iwkv_cursor_close(&cur);
  }
  iwkv_close(&iwkv);
  return rc;
}

int main() {
  iwrc rc = run();
  if (rc) {
    iwlog_ecode_error3(rc);
    return 1;
  }
  return 0;
}
```

Output:
```
>>>> Traverse in descending order
Wolverhampton Wanderers: 43
West Ham United: 27
Watford: 27
Tottenham Hotspur: 41
Southampton: 34
Sheffield United: 43
Norwich City: 21
Newcastle United: 35
Manchester United: 45
Manchester City: 57
Liverpool: 82
Leicester City: 53
Everton: 37
Crystal Palace: 39
Chelsea: 48
Burnley: 39
Brighton & Hove Albion: 29
Aston Villa: 25
Arsenal: 40
AFC Bournemouth: 27

>>>> Traverse in ascending order
AFC Bournemouth: 27
Arsenal: 40
Aston Villa: 25
Brighton & Hove Albion: 29
Burnley: 39
Chelsea: 48
Crystal Palace: 39
Everton: 37
Leicester City: 53
Liverpool: 82
Manchester City: 57
Manchester United: 45
Newcastle United: 35
Norwich City: 21
Sheffield United: 43
Southampton: 34
Tottenham Hotspur: 41
Watford: 27
West Ham United: 27
Wolverhampton Wanderers: 43

>>>> Records GE: Manchester United
Manchester United: 45
Manchester City: 57
Liverpool: 82
Leicester City: 53
Everton: 37
Crystal Palace: 39
Chelsea: 48
Burnley: 39
Brighton & Hove Albion: 29
Aston Villa: 25
Arsenal: 40
AFC Bournemouth: 27
```

# License
```

MIT License

Copyright (c) 2012-2025 Softmotions Ltd <info@softmotions.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```
///
/// Compound keys demo.
///
/// Compound keys allows associate one `key value` with many references
/// represented as VNUM64 (eg.: Non unique table indexes).
///
/// Compound mainly used for non-unique indexes in ejdb2 database engine:
///
///   `<prefix key value>.<document id>`
///

#include "iwkv.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

struct user_s {
  uint32_t id;
  char    *name;
};

struct chat_root_s {
  char *name;
  struct user_s users[5];
};

static struct chat_root_s rooms[] = {
  {
    .name = "Meeting room",
    .users ={
      { .id = 1, .name = "Joy Lynn"      },
      { .id = 2, .name = "Aubrey Sparks" },
      { .id = 3, .name = "Vinnie Kaye"   },
      { 0 }
    }
  },
  {
    .name = "Webinar room",
    .users ={
      { .id = 4, .name = "Arda Payne"    },
      { .id = 2, .name = "Joy Lynn"      },
      { 0 }
    }
  }
};

static iwrc run(void) {
  IWKV_OPTS opts = {
    .path   = "compoundkeys.db",
    .oflags = IWKV_TRUNC
  };
  IWKV iwkv;
  IWDB db;
  IWKV_cursor cur = 0;
  iwrc rc = iwkv_open(&opts, &iwkv);
  RCRET(rc);

  rc = iwkv_db(iwkv, 1, IWDB_COMPOUND_KEYS, &db);
  RCGO(rc, finish);

  // Persist all rooms with members
  for (int i = 0; i < sizeof(rooms) / sizeof(rooms[0]); ++i) {
    int j = 0;
    struct chat_root_s *room = &rooms[i];
    for (struct user_s *user = &room->users[0]; user->id; user = &room->users[++j]) {
      IWKV_val key = { .data = room->name, .size = strlen(room->name), .compound = user->id };
      IWKV_val val = { .data = user->name, .size = strlen(user->name) };
      RCC(rc, finish, iwkv_put(db, &key, &val, 0));
    }
  }

  // Get specific user from the room
  {
    IWKV_val key = { .data = "Webinar room", .size = sizeof("Webinar room") - 1, .compound = 2 };
    IWKV_val val;
    RCC(rc, finish, iwkv_get(db, &key, &val));
    fprintf(stdout, "\n>>>> Found: '%.*s' in room '%s' by id: %d\n",
            (int) val.size, (char*) val.data,
            (char*) key.data, (int) key.compound);
    iwkv_val_dispose(&val);
  }

  // Iterate over all members in `Meeting room`
  {
    size_t len = strlen(rooms[0].name);
    fprintf(stdout, "\n>>>> Iterate over all members in %s\n", rooms[0].name);
    IWKV_val val, key = { .data = rooms[0].name, .size = len };
    RCC(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_GE, &key));
    do {
      RCC(rc, finish, iwkv_cursor_get(cur, &key, &val));
      if (memcmp(key.data, rooms[0].name, MIN(key.size, len))) {
        // We rolled to end of `Meeting room` room
        iwkv_kv_dispose(&key, &val);
        break;
      }
      fprintf(stdout, "%.*s: %d %.*s\n",
              (int) key.size, (char*) key.data,
              (int) key.compound,
              (int) val.size,
              (char*) val.data);
      iwkv_kv_dispose(&key, &val);
    } while ((rc = iwkv_cursor_to(cur, IWKV_CURSOR_PREV)) == 0);
    rc = 0;
  }

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

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
    RCHECK(rc, finish, iwkv_put(db, &key, &val, 0));
  }

  fprintf(stdout, ">>>> Traverse in descending order\n");
  RCHECK(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_BEFORE_FIRST, 0));
  while ((rc = iwkv_cursor_to(cur, IWKV_CURSOR_NEXT)) == 0) {
    IWKV_val key, val;
    RCHECK(rc, finish, iwkv_cursor_get(cur, &key, &val));
    fprintf(stdout, "%.*s: %u\n",
            (int) key.size, (char *) key.data,
            *(uint8_t *) val.data);
    iwkv_kv_dispose(&key, &val);
  }
  rc = 0;
  iwkv_cursor_close(&cur);

  fprintf(stdout, "\n>>>> Traverse in ascending order\n");
  RCHECK(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_AFTER_LAST, 0));
  while ((rc = iwkv_cursor_to(cur, IWKV_CURSOR_PREV)) == 0) {
    IWKV_val key, val;
    RCHECK(rc, finish, iwkv_cursor_get(cur, &key, &val));
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
    RCHECK(rc, finish, iwkv_cursor_open(db, &cur, IWKV_CURSOR_GE, &key));
    do {
      RCHECK(rc, finish, iwkv_cursor_get(cur, &key, &val));
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

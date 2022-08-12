#include "iwkv.h"
#include <string.h>
#include <stdlib.h>

int main(void) {
  IWKV_OPTS opts = {
    .path   = "example1.db",
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
  // - Using key/value as char data
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
          (int) key.size, (char*) key.data,
          (int) val.size, (char*) val.data);

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
          (int) key.size, (char*) key.data,
          (int) val.size, (char*) val.data);

  iwkv_val_dispose(&val);
  iwkv_close(&iwkv);
  return 0;
}

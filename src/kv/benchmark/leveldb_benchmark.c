#include "bmbase.c"
#include <leveldb/c.h>

typedef struct BM_LEVELDB {
  leveldb_t *db;
  leveldb_options_t *options;
} BM_LEVELDB;


void env_setup() {
  printf("LevelDB %d.%d\n", leveldb_major_version(), leveldb_minor_version());
}

int main(int argc, char** argv) {
  return 0;
}


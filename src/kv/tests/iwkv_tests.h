#include <stdio.h>
#include <CUnit/Basic.h>

void iwkvd_trigger_xor(uint64_t val);


static int cmp_files(FILE *f1, FILE *f2) {
  CU_ASSERT_TRUE_FATAL(f1 && f2);
  fseek(f1, 0, SEEK_SET);
  fseek(f2, 0, SEEK_SET);
  char c1 = getc(f1);
  char c2 = getc(f2);
  int pos = 0, line = 1;
  while (c1 != EOF && c2 != EOF) {
    pos++;
    if (c1 == '\n' && c2 == '\n') {
      line++;
      pos = 0;
    } else if (c1 != c2) {
      fprintf(stderr, "\nDiff at: %d:%d\n", line, pos);
      return (c1 - c2);
    }
    c1 = getc(f1);
    c2 = getc(f2);
  }
  if (c1 - c2) {
    fprintf(stderr, "\nDiff at: %d:%d\n", line, pos);
  }
  return (c1 - c2);
}
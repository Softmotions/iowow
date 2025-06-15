#include <stdio.h>
#include <stdlib.h>
int main(void) {
  if (sizeof(void*) == 8) {
    puts("SYSTEM_BITNESS_64=1");
  } else if (sizeof(void*) == 4) {
    puts("SYSTEM_BITNESS_32=1");
  } else {
    puts("Unknown bitness");
    exit(1);
  }

  unsigned x = 1;
  if (*(char*)&x == 0) {
    puts("SYSTEM_BIGENDIAN=1");
  } else {
    puts("SYSTEM_LITTLE_ENDIAN=1");
  }

  return 0;
}

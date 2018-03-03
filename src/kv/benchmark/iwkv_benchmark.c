
#include "bmbase.c"
#include "iwutils.h"

struct BMENV {
  void (*print_env)(void);    
} env;

void all_run() {
  env.print_env();
}

void print_env() {
}

int main(int argc, char** argv) {
#ifndef NDEBUG
  fprintf(stdout,
          "WARNING: Assertions are enabled; benchmarks can be slow\n");
#endif
  env.print_env = print_env;
  
  all_run();  
}

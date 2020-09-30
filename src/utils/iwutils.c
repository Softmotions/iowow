//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2020 Softmotions Ltd <info@softmotions.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *************************************************************************************************/


#include "iwcfg.h"
#include "iwutils.h"
#include "iwlog.h"
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "mt19937ar.h"

#define IWU_RAND_MAX 0xffffffff

iwrc iwu_init(void) {
  init_mt19937ar();
  return 0;
}

void iwu_rand_seed(uint32_t seed) {
  init_genrand(seed);
}

uint32_t iwu_rand_u32(void) {
  return genrand_int32();
}

double_t iwu_rand_dnorm(double_t avg, double_t sd) {
  assert(sd >= 0.0);
  return sqrt(-2.0 * log((genrand_int31() / (double_t) INT_MAX))) *
         cos(2 * 3.141592653589793 * (genrand_int31() / (double_t) INT_MAX)) * sd + avg;
}

uint32_t iwu_rand_range(uint32_t range) {
  return genrand_int32() % range;
}

uint32_t iwu_rand_inorm(int range) {
  int num = (int) iwu_rand_dnorm(range >> 1, (double_t) range / 10.0);
  return (num < 0 || num >= range) ? 0 : num;
}

int iwlog2_32(uint32_t val) {
  static const int tab32[32] = {
    0,  9,  1, 10, 13, 21,  2, 29,
    11, 14, 16, 18, 22, 25,  3, 30,
    8, 12, 20, 28, 15, 17, 24,  7,
    19, 27, 23,  6, 26,  5,  4, 31
  };
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  return tab32[(val * 0x07C4ACDD) >> 27];
}

int iwlog2_64(uint64_t val) {
  static const int table[64] = {
    0, 58, 1, 59, 47, 53, 2, 60, 39, 48, 27, 54, 33, 42, 3, 61,
    51, 37, 40, 49, 18, 28, 20, 55, 30, 34, 11, 43, 14, 22, 4, 62,
    57, 46, 52, 38, 26, 32, 41, 50, 36, 17, 19, 29, 10, 13, 21, 56,
    45, 25, 31, 35, 16, 9, 12, 44, 24, 15, 8, 23, 7, 6, 5, 63
  };
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  val |= val >> 32;
  return table[(val * 0x03f6eaf2cd271461) >> 58];
}

uint32_t iwu_crc32(const uint8_t *buf, int len, uint32_t init) {

  static const unsigned int crc32_table[] = {
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
    0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
    0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
    0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
    0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
    0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
    0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
    0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
    0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
    0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
    0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
    0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
    0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
    0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
    0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
    0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
    0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
    0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
    0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
    0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
    0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
    0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
    0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
    0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
    0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
    0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
    0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
    0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
    0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
    0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
    0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
    0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
    0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
    0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
    0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
    0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
    0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
    0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
    0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
    0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
    0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
    0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
    0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
    0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
    0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
    0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
    0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
    0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
    0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
    0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
    0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
    0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
    0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
    0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
    0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
    0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
    0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
    0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
    0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
    0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
    0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
    0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
    0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
  };

  uint32_t crc = init;
  while (len--) {
    crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ *buf) & 255];
    buf++;
  }
  return crc;
}

char *iwu_replace_char(char *data, char sch, char rch) {
  for (int i = 0; data[i]; ++i) {
    if (data[i] == sch) {
      data[i] = rch;
    }
  }
  return data;
}

int iwu_cmp_files(FILE *f1, FILE *f2, bool verbose) {
  if (!f1 && !f2) {
    return 0;
  }
  if (!f1) {
    return -1;
  }
  if (!f2) {
    return 1;
  }
  fseek(f1, 0, SEEK_SET);
  fseek(f2, 0, SEEK_SET);
  int c1 = getc(f1);
  int c2 = getc(f2);
  int pos = 0, line = 1;
  while (c1 != EOF && c2 != EOF) {
    pos++;
    if (c1 == '\n' && c2 == '\n') {
      line++;
      pos = 0;
    } else if (c1 != c2) {
      if (verbose) {
        fprintf(stderr, "\nDiff at: %d:%d\n", line, pos);
      }
      return (c1 - c2);
    }
    c1 = getc(f1);
    c2 = getc(f2);
  }
  if ((c1 - c2) && verbose) { // -V793
    fprintf(stderr, "\nDiff at: %d:%d\n", line, pos);
  }
  return (c1 - c2);
}

char *iwu_file_read_as_buf(const char *path) {
  struct stat st;
  if (stat(path, &st) == -1) {
    return 0;
  }
  int fd = open(path, O_RDONLY);
  if (fd == -1) return 0;

  char *data = malloc(st.st_size + 1);
  if (!data) {
    close(fd);
    return 0;
  }
  if (st.st_size != read(fd, data, st.st_size)) {
    close(fd);
    return 0;
  }
  close(fd);
  data[st.st_size] = '\0';
  return data;
}

uint32_t iwu_x31_u32_hash(const char *s) {
  uint32_t h = (uint32_t) * s;
  if (h) {
    for (++s; *s; ++s) {
      h = (h << 5) - h + (uint32_t) * s;
    }
  }
  return h;
}

iwrc iwu_replace(IWXSTR **result,
                 const char *data,
                 int datalen,
                 const char *keys[],
                 int keysz,
                 iwu_replace_mapper mapper,
                 void *mapper_op) {

  if (!result || !data || !keys || !mapper) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  if (datalen < 1 || keysz < 1) {
    *result = iwxstr_new2(datalen < 1 ? 1 : datalen);
    if (datalen > 0) {
      rc = iwxstr_cat(*result, data, datalen);
    }
    return rc;
  }

  const char *start = data;
  const char *ptr = start;

  IWXSTR *bbuf = 0;
  IWXSTR *inter = 0;
  bbuf = iwxstr_new2(datalen);
  RCA(bbuf, finish);
  inter = iwxstr_new2(datalen);
  RCA(inter, finish);

  for (int i = 0; i < keysz; ++i) {
    iwxstr_clear(bbuf);
    const char *key = keys[i];
    size_t klen = strlen(key);
    while (true) {
      const char *p = strstr(ptr, key);
      if (!p) {
        if (ptr != start) {
          rc = iwxstr_cat(bbuf, ptr, datalen - (ptr - start));
          RCGO(rc, finish);
        }
        break;
      }
      iwxstr_cat(bbuf, ptr, p - ptr);
      const char *repl = mapper(key, mapper_op);
      rc = iwxstr_cat2(bbuf, repl ? repl : key);
      RCGO(rc, finish);
      ptr = p + klen;
      if (ptr - start >= datalen) {
        break;
      }
    }
    if (ptr != start) {
      iwxstr_clear(inter);
      rc = iwxstr_cat(inter, iwxstr_ptr(bbuf), iwxstr_size(bbuf));
      RCGO(rc, finish);
      ptr = iwxstr_ptr(inter);
      start = ptr;
      datalen = iwxstr_size(inter);
    }
  }

finish:
  if (bbuf) {
    iwxstr_destroy(bbuf);
  }
  if (!rc && start == data) {
    rc = iwxstr_cat(inter, data, datalen);
  }
  if (rc) {
    if (inter) {
      iwxstr_destroy(inter);
    }
  } else {
    *result = inter;
  }
  return rc;
}

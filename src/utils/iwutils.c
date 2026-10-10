//
/**************************************************************************************************
 * IOWOW library
 *
 * MIT License
 *
 * Copyright (c) 2012-2026 Softmotions Ltd <info@softmotions.com>
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


#include "iwutils.h"
#include "iwlog.h"
#include "iwxstr.h"
#include "iwfile.h"

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "mt19937ar.h"

// CRC-32C hardware acceleration detection.
// SSE4.2 is probed at runtime; the ARMv8 CRC extension is a compile-time
// property of the target.
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
  && (defined(__GNUC__) || defined(__clang__))
#define IWU_CRC32_X86        1
#define IWU_CRC32_X86_TARGET __attribute__((target("sse4.2")))
#include <nmmintrin.h>
#elif (defined(__aarch64__) || defined(__arm__)) && defined(__ARM_FEATURE_CRC32)
#define IWU_CRC32_ARM 1
#include <arm_acle.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

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
  return sqrt(-2.0 * log((genrand_int31() / (double_t) INT_MAX)))
         * cos(2 * 3.141592653589793 * (genrand_int31() / (double_t) INT_MAX)) * sd + avg;
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
    0, 9, 1, 10, 13, 21, 2, 29,
    11, 14, 16, 18, 22, 25, 3, 30,
    8, 12, 20, 28, 15, 17, 24, 7,
    19, 27, 23, 6, 26, 5, 4, 31
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

//-------------------------- CRC-32C (Castagnoli)

/// Portable table-driven CRC-32C (Castagnoli) reference implementation.
static uint32_t _iwu_crc32c_sw(const uint8_t *buf, int len, uint32_t crc) {
  static const uint32_t crc32c_table[256] = {
    0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4,
    0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
    0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b,
    0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
    0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b,
    0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
    0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54,
    0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
    0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a,
    0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
    0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5,
    0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
    0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45,
    0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
    0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
    0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
    0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48,
    0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
    0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687,
    0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
    0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927,
    0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
    0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8,
    0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
    0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096,
    0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
    0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859,
    0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
    0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9,
    0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
    0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36,
    0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
    0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c,
    0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
    0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043,
    0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
    0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3,
    0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
    0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c,
    0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
    0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652,
    0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
    0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d,
    0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
    0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
    0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
    0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2,
    0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
    0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530,
    0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
    0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff,
    0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
    0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f,
    0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
    0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90,
    0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
    0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee,
    0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
    0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321,
    0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
    0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81,
    0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
    0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e,
    0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
  };
  while (len-- > 0) {
    crc = (crc >> 8) ^ crc32c_table[(crc ^ *buf++) & 0xFF];
  }
  return crc;
}

#if defined(IWU_CRC32_X86)
/// SSE4.2 accelerated CRC-32C.
/// Compiled with the `sse4.2` target attribute so that the translation unit
/// itself does not have to be built with `-msse4.2`. The caller must ensure the
/// CPU supports SSE4.2 (see `iwu_crc32()`).
IWU_CRC32_X86_TARGET
static uint32_t _iwu_crc32c_hw(const uint8_t *buf, int len, uint32_t crc) {
#if defined(__x86_64__) || defined(_M_X64)
  while (len >= 8) {
    uint64_t v;
    memcpy(&v, buf, sizeof(v));
    crc = (uint32_t) _mm_crc32_u64((unsigned long long) crc, v);
    buf += 8;
    len -= 8;
  }
#endif
  if (len >= 4) {
    uint32_t v;
    memcpy(&v, buf, sizeof(v));
    crc = _mm_crc32_u32(crc, v);
    buf += 4;
    len -= 4;
  }
  if (len >= 2) {
    uint16_t v;
    memcpy(&v, buf, sizeof(v));
    crc = (uint32_t) _mm_crc32_u16(crc, v);
    buf += 2;
    len -= 2;
  }
  if (len >= 1) {
    crc = (uint32_t) _mm_crc32_u8(crc, *buf);
  }
  return crc;
}
#elif defined(IWU_CRC32_ARM)
/// ARMv8 CRC extension accelerated CRC-32C.
static uint32_t _iwu_crc32c_hw(const uint8_t *buf, int len, uint32_t crc) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  while (len >= 8) {
    uint64_t v;
    memcpy(&v, buf, sizeof(v));
    crc = __crc32cd(crc, v);
    buf += 8;
    len -= 8;
  }
  if (len >= 4) {
    uint32_t v;
    memcpy(&v, buf, sizeof(v));
    crc = __crc32cw(crc, v);
    buf += 4;
    len -= 4;
  }
  if (len >= 2) {
    uint16_t v;
    memcpy(&v, buf, sizeof(v));
    crc = __crc32ch(crc, v);
    buf += 2;
    len -= 2;
  }
  if (len >= 1) {
    crc = __crc32cb(crc, *buf);
  }
  return crc;
#else
  // Byte-wise variant is endianness independent.
  while (len-- > 0) {
    crc = __crc32cb(crc, *buf++);
  }
  return crc;
#endif
}
#endif

/// Compute the CRC-32C (Castagnoli) checksum of @a buf.
///
/// Unlike the classic CRC-32 (IEEE 802.3), CRC-32C uses the Castagnoli
/// polynomial (0x1EDC6F41) and is natively computed by the x86 SSE4.2 `crc32`
/// instruction as well as the ARMv8 CRC32C instructions.
///
/// @a init is the initial CRC register value. Pass 0 to start a fresh
/// computation, or the value returned by a previous call to continue over a
/// concatenated buffer. No implicit complement is applied, matching the raw
/// hardware semantics. The standard CRC-32C check value can be obtained as
/// `iwu_crc32(data, len, 0xFFFFFFFFU) ^ 0xFFFFFFFFU`.
uint32_t iwu_crc32(const uint8_t *buf, int len, uint32_t init) {
#if defined(IWU_CRC32_X86)
  if (__builtin_cpu_supports("sse4.2")) {
    return _iwu_crc32c_hw(buf, len, init);
  }
#elif defined(IWU_CRC32_ARM)
  return _iwu_crc32c_hw(buf, len, init);
#endif
  return _iwu_crc32c_sw(buf, len, init);
}

#ifdef IW_TESTS
uint32_t iwu_crc32_sw(const uint8_t *buf, int len, uint32_t init) {
  return _iwu_crc32c_sw(buf, len, init);
}

uint32_t iwu_crc32_hw(const uint8_t *buf, int len, uint32_t init) {
#if defined(IWU_CRC32_X86) || defined(IWU_CRC32_ARM)
  return _iwu_crc32c_hw(buf, len, init);
#else
  return _iwu_crc32c_sw(buf, len, init);
#endif
}

bool iwu_crc32_hw_available(void) {
#if defined(IWU_CRC32_X86)
  return __builtin_cpu_supports("sse4.2");
#elif defined(IWU_CRC32_ARM)
  return true;
#else
  return false;
#endif
}
#endif

char* iwu_replace_char(char *data, char sch, char rch) {
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
    if ((c1 == '\n') && (c2 == '\n')) {
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

iwrc iwu_file_write_buf(const char *path, const char *buf, size_t len, bool append) {
  int flags = O_WRONLY | O_CREAT;
  if (append) {
    flags |= O_APPEND;
  } else {
    flags |= O_TRUNC;
  }
  int fd = open(path, flags, IWFS_DEFAULT_FILEMODE);
  if (fd == -1) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  for (ssize_t w, tow = len; tow > 0; ) {
    w = write(fd, buf + len - tow, tow);
    if (w >= 0) {
      tow -= w;
    } else if (w < 0) {
      if (errno == EAGAIN) {
        continue;
      }
      int ret = errno;
      close(fd);
      return ret;
    }
  }
  close(fd);
  return 0;
}

char* iwu_file_read_as_buf_max(const char *path, ssize_t len_max, size_t *out_len) {
  struct iwxstr *xstr = iwxstr_create_empty();
  if (!xstr) {
    return 0;
  }

  char buf[8192];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    iwxstr_destroy(xstr);
    return 0;
  }

  while (len_max != 0) {
    ssize_t rb = read(fd, buf, sizeof(buf));
    if (rb > 0) {
      if (len_max > -1) {
        if (rb > len_max) {
          rb = len_max;
        }
        len_max -= rb;
      }
      if (iwxstr_cat(xstr, buf, rb)) {
        goto error;
      }
    } else if (rb < 0) {
      if (errno != EINTR) {
        goto error;
      }
    } else {
      break;
    }
  }

  close(fd);
  *out_len = iwxstr_size(xstr);
  return iwxstr_destroy_keep_ptr(xstr);

error:
  close(fd);
  *out_len = 0;
  iwxstr_destroy(xstr);
  return 0;
}

char* iwu_file_read_as_buf_len(const char *path, size_t *out_len) {
  return iwu_file_read_as_buf_max(path, -1, out_len);
}

char* iwu_file_read_as_buf(const char *path) {
  size_t sz;
  return iwu_file_read_as_buf_len(path, &sz);
}

iwrc iwu_replace(
  struct iwxstr    **result,
  const char        *data,
  int                datalen,
  const char        *keys[],
  int                keysz,
  iwu_replace_mapper mapper,
  void              *mapper_op) {
  if (!result || !data || !keys || !mapper) {
    return IW_ERROR_INVALID_ARGS;
  }

  if (keysz < 0) {
    for (keysz = 0; keys[keysz] != 0; ++keysz) ;
  }

  iwrc rc = 0;
  if ((datalen < 1) || (keysz < 1)) {
    *result = iwxstr_create(datalen < 1 ? 1 : datalen);
    if (datalen > 0) {
      rc = iwxstr_cat(*result, data, datalen);
    }
    return rc;
  }

  const char *start = data;
  const char *ptr = start;

  struct iwxstr *bbuf = 0;
  struct iwxstr *inter = 0;
  bbuf = iwxstr_create(datalen);
  RCA(bbuf, finish);
  inter = iwxstr_create(datalen);
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
  if (!rc && (start == data)) {
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

#include "iwuuid.h"
#include "iwutils.h"
#include <string.h>

union _uuid {
  uint8_t   byte[16];
  uint32_t  rnd[4];
};

// [a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}

IW_INLINE bool _is_uuid_char(char ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
}

bool iwu_uuid_valid(const char *uuid) {
  if (!uuid || strlen(uuid) != IW_UUID_STR_LEN) {
    return false;
  }
  for (int i = 0; i < 8; ++i) {
    if (!_is_uuid_char(uuid[i])) {
      return false;
    }
  }
  if (uuid[8] != '-') {
    return false;
  }
  uuid += 9;
  for (int j = 0; j < 3; ++j) {
    for (int i = 0; i < 4; ++i) {
      if (!_is_uuid_char(uuid[i])) {
        return false;
      }
    }
    if (uuid[4] != '-') {
      return false;
    }
    uuid += 5;
  }
  for (int i = 0; i < 12; ++i) {
    if (!_is_uuid_char(uuid[i])) {
      return false;
    }
  }
  return true;
}

void iwu_uuid4_fill(char dest[static IW_UUID_STR_LEN]) {
  char buf[IW_UUID_STR_LEN + 1];
  union _uuid uuid;
  for (size_t i = 0; i < 4; i++) {
    uuid.rnd[i] = iwu_rand_u32();
  }
  uuid.byte[6] = (uuid.byte[6] & 0x0F) | 0x40;
  uuid.byte[8] = (uuid.byte[8] & 0x3F) | 0x80;
  snprintf(buf, IW_UUID_STR_LEN + 1, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           uuid.byte[0],
           uuid.byte[1],
           uuid.byte[2],
           uuid.byte[3],
           uuid.byte[4],
           uuid.byte[5],
           uuid.byte[6],
           uuid.byte[7],
           uuid.byte[8],
           uuid.byte[9],
           uuid.byte[10],
           uuid.byte[11],
           uuid.byte[12],
           uuid.byte[13],
           uuid.byte[14],
           uuid.byte[15]);
  memcpy(dest, buf, IW_UUID_STR_LEN);
}

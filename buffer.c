#include "buffer.h"

#include <string.h>

void *BufWriteByte(void *buf, uint8_t byte) {
  uint8_t *p = buf;
  *p = byte;
  return p + 1;
}

void *BufWriteNetU16(void *buf, uint16_t u16) {
  uint8_t *p = buf;
  p[0] = u16 >> 8;
  p[1] = u16 & 0xff;
  return p + 2;
}

void *BufWriteNetU32(void *buf, uint32_t u32) {
  uint8_t *p = buf;
  p[0] = u32 >> 24;
  p[1] = (u32 >> 16) & 0xff;
  p[2] = (u32 >> 8) & 0xff;
  p[3] = u32 & 0xff;
  return p + 4;
}

void *BufWriteBytes(void *buf, const void *from, size_t len) {
  memcpy(buf, from, len);
  return (uint8_t *)buf + len;
}

void *BufWriteZeros(void *buf, size_t len) {
  memset(buf, 0, len);
  return (uint8_t *)buf + len;
}

const void *BufReadByte(const void *buf, uint8_t *byte) {
  const uint8_t *p = buf;
  *byte = *p;
  return p + 1;
}

const void *BufReadNetU16(const void *buf, uint16_t *u16) {
  const uint8_t *p = buf;
  *u16 = p[0] << 8 | p[1];
  return p + 2;
}

const void *BufReadNetU32(const void *buf, uint32_t *u32) {
  const uint8_t *p = buf;
  *u32 = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
  return p + 4;
}

const void *BufReadBytes(const void *buf, void *to, size_t len) {
  memcpy(to, buf, len);
  return (const uint8_t *)buf + len;
}

const void *BufReadIgnore(const void *buf, size_t len) {
  return (const uint8_t *)buf + len;
}

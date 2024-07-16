#ifndef PCP_BUFFER_H
#define PCP_BUFFER_H

#include <stddef.h>
#include <stdint.h>

void *BufWriteByte(void *buf, uint8_t byte);
void *BufWriteNetU16(void *buf, uint16_t u16);
void *BufWriteNetU32(void *buf, uint32_t u32);
void *BufWriteBytes(void *buf, const void *from, size_t len);
void *BufWriteZeros(void *buf, size_t len);
const void *BufReadByte(const void *buf, uint8_t *byte);
const void *BufReadNetU16(const void *buf, uint16_t *u16);
const void *BufReadNetU32(const void *buf, uint32_t *u32);
const void *BufReadBytes(const void *buf, void *to, size_t len);
const void *BufReadIgnore(const void *buf, size_t len);

#endif

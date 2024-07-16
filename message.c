#include "message.h"

#include <assert.h>
#include <stdlib.h>

#include "buffer.h"

void NonceInit(struct Nonce *nonce) {
  arc4random_buf(nonce->n, sizeof(nonce->n));
}

void *WriteReqHdr(const struct ReqHdr *req, void *buf, size_t max_len) {
  if (max_len < LEN_MSG_HDR) return NULL;
  buf = BufWriteByte(buf, req->version);
  buf = BufWriteByte(buf, 0x7f & req->opcode);
  buf = BufWriteZeros(buf, 2);
  buf = BufWriteNetU32(buf, req->requested_lifetime);
  buf = BufWriteBytes(buf, &req->client_ip, sizeof(req->client_ip));
  return buf;
}

void *WriteMapInfo(const struct MapInfo *info, void *buf, size_t max_len) {
  if (max_len < LEN_MAP_INFO) return NULL;
  buf = BufWriteBytes(buf, info->mapping_nonce.n,
      sizeof(info->mapping_nonce.n));
  buf = BufWriteByte(buf, info->protocol);
  buf = BufWriteZeros(buf, 3);
  buf = BufWriteNetU16(buf, info->internal_port);
  buf = BufWriteNetU16(buf, info->external_port);
  buf = BufWriteBytes(buf, &info->external_ip, sizeof(info->external_ip));
  return buf;
}

void *WritePeerInfo(const struct PeerInfo *info, void *buf, size_t max_len) {
  if (max_len < LEN_PEER_INFO) return NULL;
  buf = BufWriteBytes(buf, info->mapping_nonce.n, sizeof(info->mapping_nonce.n));
  buf = BufWriteByte(buf, info->protocol);
  buf = BufWriteZeros(buf, 3);
  buf = BufWriteNetU16(buf, info->internal_port);
  buf = BufWriteNetU16(buf, info->external_port);
  buf = BufWriteBytes(buf, &info->external_ip, sizeof(info->external_ip));
  buf = BufWriteNetU16(buf, info->peer_port);
  buf = BufWriteZeros(buf, 2);
  buf = BufWriteBytes(buf, &info->peer_ip, sizeof(info->peer_ip));
  return buf;
}

void *WriteOption(const struct OptionHdr *option, void *buf, size_t max_len) {
  if (max_len < LEN_OPTION_HDR + option->length) return NULL;
  buf = BufWriteByte(buf, option->code);
  buf = BufWriteZeros(buf, 1);
  buf = BufWriteNetU16(buf, option->length);
  switch (option->code) {
    case OPTION_THIRD_PARTY: {
      assert(option->length == LEN_OPTION_BODY_THIRD_PARTY);
      const struct ThirdPartyOption *third =
          (const struct ThirdPartyOption *)option;
      buf = BufWriteBytes(buf, &third->internal_ip, sizeof(third->internal_ip));
      break;
    }
    case OPTION_PREFER_FAILURE: {
      assert(option->length == LEN_OPTION_BODY_PREFER_FAILURE);
      break;
    }
    case OPTION_FILTER: {
      assert(option->length == LEN_OPTION_BODY_FILTER);
      const struct FilterOption *filter = (const struct FilterOption *)option;
      buf = BufWriteZeros(buf, 1);
      buf = BufWriteByte(buf, filter->prefix_length);
      buf = BufWriteNetU16(buf, filter->peer_port);
      buf = BufWriteBytes(buf, &filter->peer_ip, sizeof(filter->peer_ip));
      break;
    }
    default: {
      // Move back the write cursor to ignore the written option header.
      return (uint8_t *)buf - LEN_OPTION_HDR;
    }
  }
  return buf;
}

const void *ReadRespHdr(const void *buf, size_t len, struct RespHdr *resp) {
  if (len < LEN_MSG_HDR) return NULL;
  buf = BufReadByte(buf, &resp->version);
  buf = BufReadByte(buf, &resp->r_opcode);
  buf = BufReadIgnore(buf, 1);
  buf = BufReadByte(buf, &resp->result_code);
  buf = BufReadNetU32(buf, &resp->lifetime);
  buf = BufReadNetU32(buf, &resp->epoch_time);
  buf = BufReadIgnore(buf, 12);
  return buf;
}

const void *ReadMapInfo(const void *buf, size_t len, struct MapInfo *info) {
  if (len < LEN_MAP_INFO) return NULL;
  buf = BufReadBytes(buf, info->mapping_nonce.n, sizeof(info->mapping_nonce.n));
  buf = BufReadByte(buf, &info->protocol);
  buf = BufReadIgnore(buf, 3);
  buf = BufReadNetU16(buf, &info->internal_port);
  buf = BufReadNetU16(buf, &info->external_port);
  buf = BufReadBytes(buf, &info->external_ip, sizeof(info->external_ip));
  return buf;
}

const void *ReadOption(const void *buf, size_t len, struct OptionHdr *option) {
  if (len < LEN_OPTION_HDR) return NULL;
  buf = BufReadByte(buf, &option->code);
  buf = BufReadIgnore(buf, 1);
  buf = BufReadNetU16(buf, &option->length);

  if (len < LEN_OPTION_HDR + option->length) return NULL;
  switch (option->code) {
    case OPTION_THIRD_PARTY: {
      if (option->length != LEN_OPTION_BODY_THIRD_PARTY) return NULL;
      struct ThirdPartyOption *third = (struct ThirdPartyOption *)buf;
      buf = BufReadBytes(buf, &third->internal_ip, sizeof(third->internal_ip));
      break;
    }
    case OPTION_PREFER_FAILURE: {
      if (option->length != LEN_OPTION_BODY_PREFER_FAILURE) return NULL;
      break;
    }
    case OPTION_FILTER: {
      if (option->length != LEN_OPTION_BODY_FILTER) return NULL;
      struct FilterOption *filter = (struct FilterOption *)buf;
      buf = BufReadIgnore(buf, 1);
      buf = BufReadByte(buf, &filter->prefix_length);
      buf = BufReadNetU16(buf, &filter->peer_port);
      buf = BufReadBytes(buf, &filter->peer_ip, sizeof(filter->peer_ip));
      break;
    }
    default: {
      buf = BufReadIgnore(buf, option->length);
      break;
    }
  }
  return buf;
}

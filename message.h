#ifndef PCP_MESSAGE_H
#define PCP_MESSAGE_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

// Lengths (# of bytes)
#define LEN_MAX_PAYLOAD 1100
#define LEN_MSG_HDR 24
#define LEN_MAP_INFO 36
#define LEN_PEER_INFO 56
#define LEN_OPTION_HDR 4
#define LEN_OPTION_BODY_THIRD_PARTY 16
#define LEN_OPTION_BODY_PREFER_FAILURE 0
#define LEN_OPTION_BODY_FILTER 20

enum ProtoVersion: uint8_t {
  NAT_PMP_VERSIOIN = 0,
  PCP_VERSION = 2,
};

enum OpCode: uint8_t {
  OPCODE_ANNOUNCE = 0,
  OPCODE_MAP = 1,
  OPCODE_PEER = 2,
};

enum ResultCode: uint8_t {
  RC_SUCCESS = 0,
  RC_UNSUPP_VERSION = 1,
  RC_NOT_AUTHORIZED = 2,
  RC_MALFORMED_REQUEST = 3,
  RC_UNSUPP_OPCODE = 4,
  RC_OPTION  = 5,
  RC_MALFORMED_OPTION = 6,
  RC_NETWORK_FAILURE = 7,
  RC_NO_RESOURCES = 8,
  RC_UNSUPP_PROTOCOL = 9,
  RC_USER_EX_QUOTA = 10,
  RC_CANNOT_PROVIDE_EXTERNAL = 11,
  RC_ADDRESS_MISMATCH = 12,
  RC_EXCESSIVE_REMOTE_PEERS = 13,
};

enum Option: uint8_t {
  OPTION_THIRD_PARTY = 1,
  OPTION_PREFER_FAILURE = 2,
  OPTION_FILTER = 3,
};

enum ReadErr {
  RE_INVALID_LENGTH = 1,
  RE_UNSUPP_VERSION = 2,
  RE_NOT_REQUEST = 3,
  RE_NOT_RESPONSE = 4,
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Version = 2  |R|   Opcode    |         Reserved              |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Requested Lifetime (32 bits)                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |            PCP Client's IP Address (128 bits)                 |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   :                                                               :
 *   :             (optional) Opcode-specific information            :
 *   :                                                               :
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   :                                                               :
 *   :             (optional) PCP Options                            :
 *   :                                                               :
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ReqHdr {
  uint8_t version;
  uint8_t opcode;
  // uint8_t _reserved[2];
  uint32_t requested_lifetime;
  struct in6_addr client_ip;
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Version = 2  |R|   Opcode    |   Reserved    |  Result Code  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                      Lifetime (32 bits)                       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                     Epoch Time (32 bits)                      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                      Reserved (96 bits)                       |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   :                                                               :
 *   :             (optional) Opcode-specific response data          :
 *   :                                                               :
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   :             (optional) Options                                :
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct RespHdr {
  uint8_t version;
  uint8_t r_opcode;
  // uint8_t _reserved_1;
  uint8_t result_code;
  uint32_t lifetime;
  uint32_t epoch_time;
  // uint8_t _reserved_2[12];
};

struct Nonce {
  uint8_t n[12];
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                 Mapping Nonce (96 bits)                       |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Protocol    |          Reserved (24 bits)                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Internal Port          |         External Port         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |       Suggested/Assigned External IP Address (128 bits)       |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct MapInfo {
  struct Nonce mapping_nonce;
  uint8_t protocol;
  // uint8_t _reserved[3];
  uint16_t internal_port;
  uint16_t external_port;
  struct in6_addr external_ip;
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                 Mapping Nonce (96 bits)                       |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Protocol    |          Reserved (24 bits)                   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |        Internal Port          |         External Port         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |       Suggested/Assigned External IP Address (128 bits)       |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       Remote Peer Port        |     Reserved (16 bits)        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |               Remote Peer IP Address (128 bits)               |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct PeerInfo {
  struct Nonce mapping_nonce;
  uint8_t protocol;
  // uint8_t _reserved_1[3];
  uint16_t internal_port;
  uint16_t external_port;
  struct in6_addr external_ip;
  uint16_t peer_port;
  // uint8_t _reserved_2[2];
  struct in6_addr peer_ip;
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  Option Code  |  Reserved     |       Option Length           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   :                       (optional) Data                         :
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct OptionHdr {
  uint8_t code;
  // uint8_t _reserved;
  uint16_t length;
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Option Code=1 |  Reserved     |   Option Length=16            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |                Internal IP Address (128 bits)                 |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ThirdPartyOption {
  struct OptionHdr hdr;
  struct in6_addr internal_ip;
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Option Code=2 |  Reserved     |   Option Length=0             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct PreferFailureOption {
  struct OptionHdr hdr;
};

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | Option Code=3 |  Reserved     |   Option Length=20            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Reserved   | Prefix Length |      Remote Peer Port         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   |               Remote Peer IP address (128 bits)               |
 *   |                                                               |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct FilterOption {
  struct OptionHdr hdr;
  // uint8_t _reserved;
  uint8_t prefix_length;
  uint16_t peer_port;
  struct in6_addr peer_ip;
};

void NonceInit(struct Nonce *nonce);

void *WriteReqHdr(const struct ReqHdr *req, void *buf, size_t max_len);
void *WriteMapInfo(const struct MapInfo *info, void *buf, size_t max_len);
void *WritePeerInfo(const struct PeerInfo *info, void *buf, size_t max_len);
void *WriteOption(const struct OptionHdr *option, void *buf, size_t max_len);

const void *ReadRespHdr(const void *buf, size_t len, struct RespHdr *resp);
const void *ReadMapInfo(const void *buf, size_t len, struct MapInfo *info);
const void *ReadOption(const void *buf, size_t len, struct OptionHdr *option);

#endif

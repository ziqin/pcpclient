#include "client.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <err.h>
#include <netinet/in.h>
#include <unistd.h>

#include "message.h"
#include "network.h"

static ssize_t SendMapReq(int sock_fd,
                          const struct sockaddr* client_addr,
                          struct Nonce mapping_nonce,
                          uint8_t protocol,
                          uint16_t port,
                          uint32_t requested_lifetime,
                          bool prefer_failure) {
  struct ReqHdr req_hdr = {
    .version = PCP_VERSION,
    .opcode = OPCODE_MAP,
    .requested_lifetime = requested_lifetime,
    .client_ip = FixedSizeAddr(client_addr),
  };
  struct MapInfo map_info = {
    .mapping_nonce = mapping_nonce,
    .protocol = protocol,
    .internal_port = port,
    .external_port = port,
    .external_ip = SuggestedExternalAddr(client_addr),
  };

  unsigned char buf[LEN_MAX_PAYLOAD], *cur;
  cur = WriteReqHdr(&req_hdr, buf, sizeof(buf));
  cur = WriteMapInfo(&map_info, cur, sizeof(buf) - (cur - buf));
  if (prefer_failure) {
    struct PreferFailureOption prefer_failure;
    prefer_failure.hdr.code = OPTION_PREFER_FAILURE;
    prefer_failure.hdr.length = LEN_OPTION_BODY_PREFER_FAILURE;
    cur = WriteOption((const struct OptionHdr *)&prefer_failure, cur,
        sizeof(buf) - (cur - buf));
  }

  return send(sock_fd, buf, cur - buf, 0);
}

static void RecvMapResp(int sock_fd, struct Nonce nonce) {
  unsigned char buf[1280];
  ssize_t size = recv(sock_fd, buf, sizeof(buf), 0);
  if (size == -1) {
    err(EXIT_FAILURE, "Failed to recv map response");
  }
  if (size < LEN_MSG_HDR || size > LEN_MAX_PAYLOAD || (size & 0x3) != 0) {
    errx(EXIT_FAILURE, "Invalid response size: %zd", size);
  }

  struct RespHdr resp_hdr;
  const unsigned char *cur = ReadRespHdr(buf, sizeof(buf), &resp_hdr);
  if (cur == NULL) {
    errx(EXIT_FAILURE, "Invalid message header");
  }
  if (resp_hdr.version != PCP_VERSION) {
    errx(EXIT_FAILURE, "Received message with unsupported protocol version");
  }
  if ((resp_hdr.r_opcode & 0x80) == 0) {
    errx(EXIT_FAILURE, "Received message is not a response");
  }
  if (resp_hdr.result_code == RC_UNSUPP_VERSION) {
    errx(EXIT_FAILURE, "Server response: unsupported protocol version");
  }
  if ((resp_hdr.r_opcode & 0x7f) != OPCODE_MAP) {
    errx(EXIT_FAILURE, "Received message is not a MAP response: opcode=%" PRIu8,
        resp_hdr.r_opcode & 0x7f);
  }

  if (resp_hdr.result_code != RC_SUCCESS) {
    errx(EXIT_FAILURE, "Server response: result_code=%" PRIu8,
        resp_hdr.result_code);
  }
  printf("Lifetime: %" PRIu32 "\n"
         "Epoch time: %" PRIu32 "\n",
         resp_hdr.lifetime, resp_hdr.epoch_time);

  struct MapInfo map_info;
  cur = ReadMapInfo(cur, sizeof(buf) - (cur - buf), &map_info);
  if (cur == NULL) {
    errx(EXIT_FAILURE, "Invalid map response specific data");
  }
  if (memcmp(&map_info.mapping_nonce, &nonce, sizeof(nonce)) != 0) {
    errx(EXIT_FAILURE, "Mapping nonce mismatch");
  }

  printf("Protocol: %" PRIu8 "\n"
         "Internal port: %" PRIu16 "\n"
         "External port: %" PRIu16 "\n",
         map_info.protocol, map_info.internal_port, map_info.external_port);
  if (IN6_IS_ADDR_V4MAPPED(&map_info.external_ip)) {
    char str[INET_ADDRSTRLEN];
    struct in_addr ipv4 = Map6To4(map_info.external_ip);
    inet_ntop(AF_INET, &ipv4, str, sizeof(str));
    printf("External IP: %s\n", str);
  } else {
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &map_info.external_ip, str, sizeof(str));
    printf("External IP: %s\n", str);
  }
}

int RunClient(const struct sockaddr* svr_addr,
              const struct sockaddr* client_addr,
              socklen_t sa_len,
              uint8_t protocol,
              uint16_t port,
              uint32_t timeout,
              bool prefer_failure) {
  struct Nonce mapping_nonce;
  NonceInit(&mapping_nonce);
  printf("Mapping nonce: ");
  for (size_t i = 0; i < sizeof(mapping_nonce.n); ++i) {
    printf("%02x", mapping_nonce.n[i]);
  }
  putchar('\n');

  int sock_fd = socket(svr_addr->sa_family, SOCK_DGRAM, 0);
  if (bind(sock_fd, client_addr, sa_len) == -1) {
    err(EXIT_FAILURE, "Failed to bind local address");
  }
  if (connect(sock_fd, svr_addr, sa_len) == -1) {
    err(EXIT_FAILURE, "Failed to connect");
  }

  ssize_t sent = SendMapReq(sock_fd, client_addr, mapping_nonce, protocol, port,
      timeout, prefer_failure);
  if (sent == -1) err(EXIT_FAILURE, "Failed to send PCP MAP request");
  RecvMapResp(sock_fd, mapping_nonce);
  close(sock_fd);
  return 0;
}

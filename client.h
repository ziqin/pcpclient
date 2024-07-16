#ifndef PCP_CLIENT_H
#define PCP_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

int RunClient(const struct sockaddr* svr_addr,
              const struct sockaddr* local_addr,
              socklen_t sa_len,
              uint8_t protocol,
              uint16_t port,
              uint32_t timeout,
              bool prefer_failure);

#endif

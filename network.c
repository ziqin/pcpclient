#include "network.h"

#include <assert.h>
#include <netinet/in.h>
#include <string.h>

struct in6_addr Map4To6(struct in_addr ipv4) {
  struct in6_addr ipv6 = {.s6_addr = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  }};
  memcpy(ipv6.s6_addr + 12, &ipv4.s_addr, 4);
  return ipv6;
}

struct in_addr Map6To4(struct in6_addr ipv4_mapped_ipv6) {
  struct in_addr ipv4;
  assert(IN6_IS_ADDR_V4MAPPED(&ipv4_mapped_ipv6));
  memcpy(&ipv4.s_addr, ipv4_mapped_ipv6.s6_addr + 12, 4);
  return ipv4;
}

struct in6_addr FixedSizeAddr(const struct sockaddr* addr) {
  switch (addr->sa_family) {
    case AF_INET:
      return Map4To6(((const struct sockaddr_in*)addr)->sin_addr);
    case AF_INET6:
      return ((const struct sockaddr_in6*)addr)->sin6_addr;
    default:
      return in6addr_any;
  }
}

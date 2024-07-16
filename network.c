#include "network.h"

#include <assert.h>
#include <netinet/in.h>
#include <string.h>

#ifndef IN6_IS_ADDR_GLOBAL
// IPv6 GUA prefix: 2001::/3
#define IN6_IS_ADDR_GLOBAL(a) (((a)->s6_addr[0] & 0xe0) == 0x20)
#endif

#ifndef IN6ADDR_V4MAPPED_INIT
// IPv4-mapped IPv6 prefix: ::ffff:0.0.0.0/96
#define IN6ADDR_V4MAPPED_INIT { .s6_addr = {       \
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  \
  0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }};
#endif

struct in6_addr Map4To6(struct in_addr ipv4) {
  struct in6_addr ipv6 = IN6ADDR_V4MAPPED_INIT;
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

struct in6_addr SuggestedExternalAddr(const struct sockaddr *addr) {
  switch (addr->sa_family) {
    case AF_INET: {
      struct in6_addr ipv4_mapped_any = IN6ADDR_V4MAPPED_INIT;
      return ipv4_mapped_any;
    }
    case AF_INET6: {
      const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)addr;
      return IN6_IS_ADDR_GLOBAL(&sa6->sin6_addr) ? sa6->sin6_addr : in6addr_any;
    }
    default:
      return in6addr_any;
  }
}

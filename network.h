#ifndef PCP_NETWORK_H
#define PCP_NETWORK_H

#include <sys/socket.h>
#include <netinet/in.h>

struct in6_addr Map4To6(struct in_addr ipv4);

struct in_addr Map6To4(struct in6_addr ipv4_mapped_ipv6);

struct in6_addr FixedSizeAddr(const struct sockaddr* addr);

#endif

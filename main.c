#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "client.h"

#define PCP_SERVER_PORT 5351

#define STR(s) #s
#define XSTR(s) STR(s)

static void usage(FILE* f) {
  fprintf(f, "Usage:\n"
      "\tpcpclient -s <server_address> -l <local_address> -p <port>\n"
      "\t          [-t | -u] [-d <timeout>]\n");
}

int main(int argc, char *argv[]) {
  bool prefer_failure = false;
  uint8_t protocol = IPPROTO_TCP;
  uint16_t port = 0;
  uint32_t timeout = 120;
  struct addrinfo hint, *svr_ai = NULL, *local_ai = NULL;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family = PF_UNSPEC;
  hint.ai_socktype = SOCK_DGRAM;
  hint.ai_protocol = IPPROTO_UDP;
  hint.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV;

  int ch;
  while ((ch = getopt(argc, argv, "s:l:p:d:tufh")) != -1) {
    switch (ch) {
      case 's':
        if (getaddrinfo(optarg, XSTR(PCP_SERVER_PORT), &hint, &svr_ai) != 0) {
          errx(EXIT_FAILURE, "Invalid server address: %s", optarg);
        }
        break;
      case 'l':
        if (getaddrinfo(optarg, NULL, &hint, &local_ai) != 0) {
          errx(EXIT_FAILURE, "Invalid local address: %s", optarg);
        }
        break;
      case 'h':
        usage(stdout);
        exit(EXIT_SUCCESS);
      case 'p':
        port = atoi(optarg);
        break;
      case 'd':
        timeout = atoi(optarg);
        break;
      case 't':
        protocol = IPPROTO_TCP;
        break;
      case 'u':
        protocol = IPPROTO_UDP;
        break;
      case 'f':
        prefer_failure = true;
        break;
      case '?':
      default:
        usage(stderr);
        exit(EXIT_FAILURE);
    }
  }
  if (svr_ai == NULL || local_ai == NULL || port == 0) {
    usage(stderr);
    exit(EXIT_FAILURE);
  }
  if (local_ai != NULL &&
      (svr_ai->ai_family != local_ai->ai_family ||
       svr_ai->ai_addrlen != local_ai->ai_addrlen)) {
    errx(EXIT_FAILURE, "Address family mismatch");
  }

  if (RunClient(svr_ai->ai_addr,
                local_ai ? local_ai->ai_addr : NULL,
                svr_ai->ai_addrlen,
                protocol,
                port,
                timeout,
                prefer_failure) == -1) {
    err(EXIT_FAILURE, "RunClient failed");
  }

  freeaddrinfo(svr_ai);
  freeaddrinfo(local_ai);

  return 0;
}

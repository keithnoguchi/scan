#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"
#include "scanner4_tcp.h"

void scanner4_init_const(struct scanner *sc)
{
}

int scanner4_init(struct scanner *sc)
{
	switch (sc->dst->ai_protocol) {
	case IPPROTO_TCP:
		return scanner4_tcp_init(sc);
	default:
		warn("TCP is the only supported protocol in IPv4\n");
		return -1;
	}
}

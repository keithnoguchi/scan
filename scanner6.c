#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"
#include "scanner6_tcp.h"

static char addr[INET6_ADDRSTRLEN];

static bool is_ll_addr(struct scanner *sc, const struct sockaddr *sa)
{
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *) sa;
	inet_ntop(sc->dst->ai_family, &sin->sin6_addr, sc->addr,
			sc->addrstr_len);
	debug("scanner6_is_ll_addr(%s)\n", sc->addr);
	return IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr);
}

void scanner6_init_const(struct scanner *sc)
{
	sc->addrstr_len = INET6_ADDRSTRLEN;
	sc->addr = addr;

	/* Address validators. */
	sc->is_ll_addr = is_ll_addr;
}

int scanner6_init(struct scanner *sc)
{
	struct sockaddr_in6 *sin;
	struct in6_pktinfo ipi;
	int ret;

	sin = (struct sockaddr_in6 *) &sc->src;
	ipi.ipi6_addr = sin->sin6_addr;
	ret = setsockopt(sc->rawfd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi,
			sizeof(ipi));
	if (ret != 0)
		fatal("setsockopt(IPV6_PKTINFO)");

	inet_ntop(sc->dst->ai_family, &sin->sin6_addr, sc->addr,
			sc->addrstr_len);
	debug("Send from %s\n", sc->addr);

	switch (sc->dst->ai_protocol) {
	case IPPROTO_TCP:
		ret = scanner6_tcp_init(sc);
		break;
	default:
		warn("TCP is the only supported protocol in IPv6\n");
		ret = -1;
		break;
	}
	return ret;
}

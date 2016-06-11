#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"
#include "scanner.h"

static char addr[INET6_ADDRSTRLEN];

static bool is_ll_addr(struct scanner *sc, const struct sockaddr *sa)
{
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *) sa;
	inet_ntop(sc->dst->ai_family, &sin->sin6_addr, addr, sizeof(addr));
	debug("scanner6_is_ll_addr(%s)\n", addr);
	return IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr);
}

void scanner6_init_const(struct scanner *sc)
{
	/* Address validators. */
	sc->is_ll_addr = is_ll_addr;
}

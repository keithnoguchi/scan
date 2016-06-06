#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "utils.h"

struct scanner {
	int family;
	int type;
	int protocol;
	int fd;
};

void init(struct scanner *sc)
{
	sc->fd = socket(sc->family, sc->type, sc->protocol);
	if (sc->fd == -1)
		fatal("socket(2)");
}

void term(struct scanner *sc)
{
	if (sc->fd != -1)
		close(sc->fd);
	sc->fd = -1;
}

int main(int argc, char *argv[])
{
	struct scanner sc;
	int sock;
	int ev;

	/* This will be set through the command line. */
	sc.family = AF_INET;
	sc.type = SOCK_STREAM;
	sc.protocol = IPPROTO_TCP;
	init(&sc);

	ev = epoll_create1(0);
	if (ev == -1)
		fatal("epoll_create1(2)");

	close(ev);
	term(&sc);

	exit(EXIT_SUCCESS);
}

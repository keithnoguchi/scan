#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "utils.h"

struct scanner {
	int fd;
	int family;
	int type;
	int protocol;
	int (*reader)(struct scanner *sc);
	int (*writer)(struct scanner *sc);
};

void init(struct scanner *sc, int eventfd, int family, int proto)
{
	struct epoll_event ev;
	int ret;

	sc->family = family;
	sc->protocol = proto;
	sc->fd = socket(sc->family, SOCK_RAW, sc->protocol);
	if (sc->fd == -1)
		fatal("socket(2)");

	/* We'll set this later. */
	sc->reader = NULL;
	sc->writer = NULL;

	/* Register to the event manager. */
	ev.events = EPOLLIN|EPOLLOUT;
	ev.data.fd = sc->fd;
	ev.data.ptr = (void *)sc;
	ret = epoll_ctl(eventfd, EPOLL_CTL_ADD, sc->fd, &ev);
	if (ret == -1)
		fatal("epoll_ctl(2)");
}

void term(struct scanner *sc)
{
	if (sc->fd != -1)
		close(sc->fd);
	sc->fd = -1;
}

static inline void reader(struct scanner *sc)
{
	if (sc->reader)
		(*sc->reader)(sc);
}

static inline void writer(struct scanner *sc)
{
	if (sc->writer)
		(*sc->writer)(sc);
}

int main(int argc, char *argv[])
{
	struct scanner sc;
	int fd;

	fd = epoll_create1(0);
	if (fd == -1)
		fatal("epoll_create1(2)");

	/* Initialize scanner. */
	init(&sc, fd, AF_INET, IPPROTO_TCP);

	for (;;) {
		struct epoll_event ev;
		struct scanner *scp;
		int nfds;

		nfds = epoll_wait(fd, &ev, 1, -1);
		if (nfds == -1)
			fatal("epoll_wait(2)");

		scp = (struct scanner *) ev.data.ptr;
		if (ev.events & EPOLLIN)
			reader(scp);
		if (ev.events & EPOLLOUT)
			writer(scp);
	}

	term(&sc);
	close(fd);

	exit(EXIT_SUCCESS);
}

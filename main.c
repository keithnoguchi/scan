#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "utils.h"

static const int start_port = 0;
static const int end_port = 65535;

struct scanner {
	int eventfd;
	int fd;
	int family;
	int proto;
	int next_port;
	int start_port;
	int end_port;
	int (*reader)(struct scanner *sc);
	int (*writer)(struct scanner *sc);
};

static int __reader(struct scanner *sc)
{
	printf("reader\n");
	return 0;
}

static int __writer(struct scanner *sc)
{
	if (++sc->next_port > sc->end_port) {
		struct epoll_event ev;

		ev.events = EPOLLIN;
		ev.data.fd = sc->fd;
		epoll_ctl(sc->eventfd, EPOLL_CTL_MOD, sc->fd, &ev);
		printf("done with sending\n");
	}
	return 0;
}

void init(struct scanner *sc, int eventfd, int family, int proto)
{
	struct epoll_event ev;
	int ret;

	sc->eventfd = eventfd;
	sc->family = family;
	sc->proto = proto;
	sc->fd = socket(sc->family, SOCK_RAW, sc->proto);
	if (sc->fd == -1)
		fatal("socket(2)");

	/* We'll set this later. */
	sc->start_port = start_port;
	sc->end_port = end_port;
	sc->next_port = sc->start_port;
	sc->reader = __reader;
	sc->writer = __writer;

	/* Register it to the event manager. */
	ev.events = EPOLLIN|EPOLLOUT;
	ev.data.fd = sc->fd;
	ev.data.ptr = (void *)sc;
	ret = epoll_ctl(sc->eventfd, EPOLL_CTL_ADD, sc->fd, &ev);
	if (ret == -1)
		fatal("epoll_ctl(2)");
}

void term(struct scanner *sc)
{
	if (sc->fd != -1) {
		epoll_ctl(sc->eventfd, EPOLL_CTL_DEL, sc->fd, NULL);
		close(sc->fd);
	}
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
	int eventfd;

	eventfd = epoll_create1(0);
	if (eventfd == -1)
		fatal("epoll_create1(2)");

	/* Initialize scanner. */
	init(&sc, eventfd, AF_INET, IPPROTO_TCP);

	for (;;) {
		struct epoll_event ev;
		struct scanner *scp;
		int nfds;

		nfds = epoll_wait(eventfd, &ev, 1, -1);
		if (nfds == -1)
			fatal("epoll_wait(2)");

		scp = (struct scanner *) ev.data.ptr;
		if (ev.events & EPOLLIN)
			reader(scp);
		if (ev.events & EPOLLOUT)
			writer(scp);
	}

	term(&sc);
	close(eventfd);

	exit(EXIT_SUCCESS);
}

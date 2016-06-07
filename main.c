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
	/* Event manager. */
	struct epoll_event ev;

	/* Sockets. */
	int eventfd;
	int rawfd;

	/* Scanning port info. */
	int next_port;
	int start_port;
	int end_port;

	/* Reader and writer of the raw socket. */
	int (*reader)(struct scanner *sc);
	int (*writer)(struct scanner *sc);
};

static inline void scanner_reader(struct scanner *sc)
{
	if (sc->reader)
		(*sc->reader)(sc);
}

static inline void scanner_writer(struct scanner *sc)
{
	if (sc->writer)
		(*sc->writer)(sc);
}

static int reader(struct scanner *sc)
{
	printf("reader\n");
	return 0;
}

static int writer(struct scanner *sc)
{
	if (++sc->next_port > sc->end_port) {
		/* Disable writer event. */
		sc->ev.events &= ~EPOLLOUT;
		epoll_ctl(sc->eventfd, EPOLL_CTL_MOD, sc->rawfd, &sc->ev);
		printf("done with sending\n");
	}
	return 0;
}

int scanner_wait(struct scanner *sc)
{
	int nfds;

	nfds = epoll_wait(sc->eventfd, &sc->ev, 1, -1);
	if (nfds == -1)
		fatal("epoll_wait(2)");

	return 1;
}

void scanner_exec(struct scanner *sc)
{
	struct scanner *scp = (struct scanner *) sc->ev.data.ptr;

	if (sc->ev.events & EPOLLIN)
		scanner_reader(scp);
	if (sc->ev.events & EPOLLOUT)
		scanner_writer(scp);
}

void scanner_init(struct scanner *sc, int family, int proto)
{
	int ret;

	sc->eventfd = epoll_create1(0);
	if (sc->eventfd == -1)
		fatal("epoll_create1(2)");

	sc->rawfd = socket(family, SOCK_RAW, proto);
	if (sc->rawfd == -1)
		fatal("socket(2)");

	/* We'll set this later. */
	sc->start_port = start_port;
	sc->end_port = end_port;
	sc->next_port = sc->start_port;
	sc->reader = reader;
	sc->writer = writer;

	/* Register it to the event manager. */
	sc->ev.events = EPOLLIN|EPOLLOUT;
	sc->ev.data.fd = sc->rawfd;
	sc->ev.data.ptr = (void *)sc;
	ret = epoll_ctl(sc->eventfd, EPOLL_CTL_ADD, sc->rawfd, &sc->ev);
	if (ret == -1)
		fatal("epoll_ctl(2)");
}

void scanner_term(struct scanner *sc)
{
	if (sc->eventfd == -1)
		return;

	if (sc->rawfd != -1) {
		epoll_ctl(sc->eventfd, EPOLL_CTL_DEL, sc->rawfd, NULL);
		close(sc->rawfd);
	}
	close(sc->eventfd);
	sc->eventfd = sc->rawfd = -1;
}

int main(int argc, char *argv[])
{
	struct scanner sc;

	/* Initialize the scanner. */
	scanner_init(&sc, AF_INET, IPPROTO_TCP);

	/* Event machine. */
	while (scanner_wait(&sc))
		scanner_exec(&sc);

	/* Terminate the scanner. */
	scanner_term(&sc);

	exit(EXIT_SUCCESS);
}

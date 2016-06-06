#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "utils.h"

int main(int argc, char *argv[])
{
	int fd;

	fd = epoll_create1(0);
	if (fd != -1)
		fatal("epoll_create1(2)");

	close(fd);

	exit(EXIT_SUCCESS);
}

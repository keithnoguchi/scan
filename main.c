#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "scanner.h"

const int scanner_default_start_port = 0;
const int scanner_default_end_port = 65535;
char *const scanner_default_ifname = NULL;

int main(int argc, char *argv[])
{
	int start_port = scanner_default_start_port;
	int end_port = scanner_default_end_port;
	char *ifname = scanner_default_ifname;
	struct scanner sc;
	char *dstname;

	if (argc < 2) {
		printf("Usage: %s <hostname>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	dstname = argv[1];
	if (argc >= 3) {
		start_port = end_port = atoi(argv[2]);
	}
	if (argc >= 4)
		ifname = argv[3];

	/* Initialize the scanner with the hostname, address family,
	 * and the protocol. */
	scanner_init(&sc, dstname, PF_INET, IPPROTO_TCP, start_port,
			end_port, ifname);

	/* Light the fire! */
	while (scanner_wait(&sc))
		scanner_exec(&sc);

	/* Done with the scanning. */
	scanner_term(&sc);

	exit(EXIT_SUCCESS);
}

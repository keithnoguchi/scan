#include <stdint.h>

#include "tracker.h"

static const unsigned short default_begin_port = 1;
static const unsigned short default_end_port = UINT16_MAX;

void tracker_print(const struct tracker *t)
{
	int port;

	printf("\nOpen ports on %s\n\n", t->addr);

	for (port = t->begin; port <= t->end; port++)
		if (t->status[port] == OPEN)
			printf("%d ", port);

	printf("\n");
}

void tracker_init(struct tracker *t, const unsigned short begin_port,
		const unsigned short end_port, char *const addr)
{
	unsigned short begin = begin_port, end = end_port;
	int i;

	/* Wrong range back to the default range. */
	if (end != 0 && begin > end)
		begin = end = 0;

	/* Member variables. */
	t->addr = addr;
	t->begin = begin ? begin : default_begin_port;
	t->end = end ? end : default_end_port;
	t->next = t->begin;

	/* Reset the port status. */
	for (i = 0; i < t->begin; i++)
		t->status[i] = UNKNOWN;

	for (i = t->begin; i <= t->end; i++)
		t->status[i] = INIT;

	for (i = t->end + 1; i < UINT16_MAX; i++)
		t->status[i] = UNKNOWN;
}

void tracker_term(struct tracker *t)
{
	int i;

	for (i = 0; i <= UINT16_MAX; i++)
		t->status[i] = UNKNOWN;
}

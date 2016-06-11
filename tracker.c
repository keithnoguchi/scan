#include <stdint.h>

#include "tracker.h"

static const unsigned short default_start_port = 1;
static const unsigned short default_end_port = UINT16_MAX;

void tracker_init(struct tracker *t, const unsigned short start,
		const unsigned short end)
{
	int i;

	/* Member variables. */
	t->start = start ? start : default_start_port;
	t->end = end ? end : default_end_port;
	t->next = t->start;

	/* Reset the port status. */
	for (i = 0; i < t->start; i++)
		t->status[i] = UNKNOWN;

	for (i = t->start; i <= t->end; i++)
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

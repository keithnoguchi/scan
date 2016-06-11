#include <stdint.h>

#include "tracker.h"

void tracker_init(struct tracker *t, const unsigned short start,
		const unsigned short end)
{
	int i;

	/* Member variables. */
	t->start = start;
	t->end = end;
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

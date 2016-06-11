#include <stdint.h>

#include "tracker.h"

void tracker_init(struct tracker *t)
{
	int i;

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
